package org.logstashplugins.hec;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Optional cooked S2S TCP listener for the captured latest-UF/HF v4 profile.
 * TLS is the same transport policy/identity as HTTP. TCP has no HEC token header:
 * transport trust (optionally mTLS) is distinct from the sender-declared GUID.
 * The GUID namespaces source IDs but is not presented as authenticated identity.
 *
 * Each connection owns a persistent compact metadata dictionary. Event records
 * are completely parsed/mapped before insertion; an FB ACK is written only after
 * all maps from that record reach the queue. Waiting on the shared processing
 * gate or the queue stops socket reads and applies ordinary TCP flow control.
 */
final class S2STcpServer implements AutoCloseable{
    private final Limits limits;
    private final IngressResources resources;
    private final Consumer<Map<String,Object>> sink;
    private final Consumer<String> diagnostic;
    private final String defaultIndex;
    private final Set<String> indexes;
    private final ServerSocket listener;
    private final Map<Socket,Thread> workers=new HashMap<>();
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"s2s-tcp-deadlines");t.setDaemon(true);return t;});
    private final AtomicLong lastWarning=new AtomicLong();
    private final Thread acceptor;
    private volatile boolean stopped;
    private volatile IOException failure;

    S2STcpServer(String host,int port,TlsConfig tls,Limits limits,IngressResources resources,
                 Consumer<Map<String,Object>> sink,String defaultIndex,Set<String> indexes,Consumer<String> diagnostic)throws IOException{
        this.limits=limits;this.resources=resources;this.sink=sink;this.defaultIndex=defaultIndex;this.indexes=Set.copyOf(indexes);this.diagnostic=diagnostic;
        if(defaultIndex.isBlank())throw new IllegalArgumentException("TCP default index must not be blank");
        deadlines.setRemoveOnCancelPolicy(true);listener=tls.bind(host,port,limits.connections());
        acceptor=Thread.ofVirtual().name("s2s-tcp-accept").unstarted(this::accept);
    }
    void start(){acceptor.start();}
    int port(){return listener.getLocalPort();}
    IOException failure(){return failure;}
    private void accept(){
        while(!stopped)try{
            Socket socket=listener.accept();
            if(!resources.connections.tryAcquire()){socket.close();continue;}
            synchronized(workers){
                if(stopped){socket.close();resources.connections.release();continue;}
                Thread worker=Thread.ofVirtual().name("s2s-tcp-peer").unstarted(()->handle(socket));workers.put(socket,worker);worker.start();
            }
        }catch(IOException error){if(!stopped){failure=error;stopAdmission();}}
    }
    private ScheduledFuture<?> deadline(Socket socket){
        return deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},limits.readMillis(),TimeUnit.MILLISECONDS);
    }
    private void handle(Socket socket){
        boolean admitted=false;
        ScheduledFuture<?> io=null;
        InputStream records=null;
        try(var header=resources.memory.lease();var infoMemory=resources.memory.lease()){
            header.charge(256L<<10);io=deadline(socket);socket.setSoTimeout(limits.readMillis());
            if(socket instanceof SSLSocket ssl)ssl.startHandshake();
            InputStream input=new BufferedInputStream(socket.getInputStream(),8192);OutputStream output=socket.getOutputStream();
            var greeting=S2STcpProtocol.greeting(input);
            if(!resources.processing.tryAcquire(limits.admissionMillis(),TimeUnit.MILLISECONDS))throw HecException.busy();admitted=true;
            boolean requestedAck,compressed;
            try(var capabilityMemory=resources.memory.lease()){
                var capabilities=S2STcpProtocol.frame(input,limits,capabilityMemory);
                String text=capabilities.pairs().get("__s2s_capabilities");
                if(text==null)throw new IOException("missing TCP capabilities");
                requestedAck=S2STcpProtocol.capability(text,"ack");compressed=S2STcpProtocol.capability(text,"compression");
                if(capabilities.compressed()&&!compressed)throw new IOException("inconsistent TCP compression request");
                S2STcpProtocol.hello(output);
            }
            var info=S2STcpProtocol.frame(input,limits,infoMemory);
            if(!S2STcpProtocol.capability(info.pairs().get("__s2s_capabilities"),"v4"))throw new IOException("compact TCP v4 was not negotiated");
            String guid=info.pairs().get("_guid");
            if(guid==null||!guid.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IOException("missing/invalid sender GUID");
            guid=guid.toLowerCase(Locale.ROOT);
            Map<String,Object> connectionInfo=new LinkedHashMap<>();
            connectionInfo.put("protocol","s2s-v4");connectionInfo.put("sender_guid",guid);
            connectionInfo.put("sender_hostname",greeting.hostname());connectionInfo.put("management_port",greeting.managementPort());
            connectionInfo.put("peer_ip",socket.getInetAddress().getHostAddress());
            connectionInfo.put("compression_requested",compressed);connectionInfo.put("ack_requested",requestedAck);
            // ForwarderInfo is protocol/connection provenance, not a fabricated
            // application log event. Never copy token/credential control fields.
            Map<String,String> safeInfo=new LinkedHashMap<>();
            info.pairs().forEach((key,value)->{String lower=key.toLowerCase(Locale.ROOT);if(!lower.contains("token")&&!lower.contains("password")&&!lower.contains("secret"))safeInfo.put(key,value);});
            connectionInfo.put("forwarder_info",Map.copyOf(safeInfo));
            var policy=new TokenStore.Token("tcp:"+TokenStore.fingerprint(guid),false,
                Map.of("index",defaultIndex,"host",greeting.hostname()),indexes,false,false,false,600_000_000_000L);
            resources.processing.release();admitted=false;io.cancel(false);io=null;socket.setSoTimeout(0);
            records=input;
            // Real latest TLS senders were observed to send the F9/zlib record stream
            // although their capability string said compression=0, so the stream
            // itself decides. A sender that requested compression must still use it.
            input.mark(1);int marker=input.read();if(marker<0)return;
            boolean streamCompressed=marker==0xf9;
            if(compressed&&!streamCompressed)throw new IOException("missing compact zlib marker");
            if(streamCompressed)records=new S2STcpProtocol.Inflated(input);else input.reset();
            connectionInfo.put("stream_compressed",streamCompressed);
            HecProtocol protocol=new HecProtocol(limits);S2SEvents mapper=new S2SEvents(limits,protocol);
            try(var session=new S2SDecoder(limits).new StreamSession()){
                int opcode;
                while(!stopped&&(opcode=records.read())>=0){
                    // No detached writer or early ACK: a full queue keeps this
                    // owned worker blocked and stops reading further peer bytes.
                    resources.processing.acquire();admitted=true;
                    var memory=resources.memory.lease();boolean retained=false;
                    try{
                        if(stopped||Thread.currentThread().isInterrupted())throw HecException.busy();
                        socket.setSoTimeout(limits.readMillis());io=deadline(socket);
                        var record=session.read(opcode,records,memory);retained=record.retainsLease();
                        io.cancel(false);io=null;socket.setSoTimeout(0);
                        List<Map<String,Object>> events=record.event()==null||record.event().control()?List.of():
                            mapper.mapWithIdentity(List.of(record.event()),policy,Map.of(),record.wireSha256(),memory);
                        for(var event:events){
                            memory.charge(2048);
                            @SuppressWarnings("unchecked") var original=(Map<String,Object>)((Map<?,?>)event.get("@metadata")).get("splunk_hec");
                            Map<String,Object> metadata=new LinkedHashMap<>(original);
                            Map<String,Object> transport=new LinkedHashMap<>(connectionInfo);
                            if(record.eventId()!=null)transport.put("event_id",Long.toUnsignedString(record.eventId()));
                            metadata.put("tcp",transport);event.put("@metadata",Map.of("splunk_hec",metadata));
                            protocol.validateLogicalSize(event,memory);
                        }
                        for(var event:events){if(stopped||Thread.currentThread().isInterrupted())throw HecException.busy();sink.accept(event);}
                        if(requestedAck&&record.eventId()!=null&&record.eventId()!=0){
                            // Latest peers' zero-ID terminal/heartbeat records have
                            // no reverse ACK in the real receiver captures.
                            io=deadline(socket);S2STcpProtocol.ack(output,record.eventId());io.cancel(false);io=null;
                        }
                    }finally{
                        if(io!=null){io.cancel(false);io=null;}
                        if(!retained)memory.close();resources.processing.release();admitted=false;
                    }
                }
            }
        }catch(Exception error){
            // Ordinary peer closes/resets/timeouts are not diagnostics.
            if(!stopped&&!(error instanceof EOFException)&&!(error instanceof SocketException)){long now=System.currentTimeMillis(),before=lastWarning.get();if(now-before>=60000&&lastWarning.compareAndSet(before,now))diagnostic.accept("S2S TCP connection closed before further acceptance ("+error.getClass().getSimpleName()+(error instanceof HecException failure?": "+failure.getMessage()+"; queue/resource pressure, a malformed record or an event above s2s_tcp_max_event_bytes":
                error.getClass().getSimpleName().equals("QueueRuntimeException")?": "+String.valueOf(error.getMessage()).substring(0,Math.min(160,String.valueOf(error.getMessage()).length()))+"; the sender will retry. A persistent queue rejects events larger than queue.page_capacity":"")+")");}
        }finally{
            if(io!=null)io.cancel(false);
            if(admitted)resources.processing.release();
            if(records instanceof S2STcpProtocol.Inflated inflated)try{inflated.close();}catch(IOException ignored){}
            try{socket.close();}catch(IOException ignored){}
            synchronized(workers){workers.remove(socket);workers.notifyAll();}resources.connections.release();
        }
    }
    private void stopAdmission(){stopped=true;try{listener.close();}catch(IOException ignored){}}
    void beginStop(){
        stopAdmission();deadlines.shutdownNow();
        synchronized(workers){for(var entry:workers.entrySet()){try{entry.getKey().close();}catch(IOException ignored){}entry.getValue().interrupt();}}
    }
    @Override public void close(){closeBy(System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(limits.shutdownMillis()));}
    void closeBy(long deadline){
        boolean interrupted=Thread.interrupted();
        try{
            beginStop();List<Thread> joining;
            synchronized(workers){joining=new ArrayList<>(workers.values());}joining.add(acceptor);
            for(Thread thread:joining)while(thread.isAlive()){
                long left=deadline-System.nanoTime();if(left<=0)break;
                try{thread.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(left)));}catch(InterruptedException stop){interrupted=true;}
            }
            if(joining.stream().anyMatch(Thread::isAlive))throw new IllegalStateException("S2S TCP worker shutdown deadline exceeded");
            while(!deadlines.isTerminated()){
                long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException("S2S TCP timers did not terminate");
                try{deadlines.awaitTermination(left,TimeUnit.NANOSECONDS);}catch(InterruptedException stop){interrupted=true;}
            }
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
}
