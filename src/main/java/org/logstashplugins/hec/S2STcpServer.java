package org.logstashplugins.hec;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Optional classic Splunk "cooked" S2S TCP listener (UF/HF {@code tcpout}, port
 * 9997 by default) for the compact "v4" profile captured from the latest real
 * forwarders.
 *
 * <h2>Threading model</h2>
 * One virtual "acceptor" thread accepts sockets. Each accepted connection gets
 * its own virtual worker thread running {@link #handle}, which is the only code
 * that ever reads from or writes to that socket. Workers are tracked in
 * {@link #workers} so shutdown can close and JOIN every one of them: no worker may
 * keep inserting events into the Logstash queue after {@link #close()} returns.
 *
 * <h2>Trust model</h2>
 * The classic protocol has no HEC token. Whoever can reach this port can send
 * events, so the boundary is the network plus (optionally) TLS/mTLS configured
 * by the caller through the {@link TlsConfig} passed in. The sender's {@code _guid}
 * namespaces event IDs but is self-declared, never presented as authenticated.
 *
 * <h2>Delivery guarantee</h2>
 * Each connection owns a persistent compact metadata dictionary (channels). A
 * record is read and mapped completely BEFORE anything is inserted; the
 * {@code FB} acknowledgement is written only AFTER every event of that record has
 * been accepted by the Logstash queue. If the queue is slow or full, the worker
 * simply blocks, stops reading the socket, and ordinary TCP flow control pushes
 * back on the sender. A failure closes the connection WITHOUT an ACK, so the
 * sender resends (a prefix may already be queued; IDs stay stable).
 */
final class S2STcpServer implements AutoCloseable{
    /** Resource limits for TCP (may carry a larger event cap than HTTP, see s2s_tcp_max_event_bytes). */
    private final Limits limits;
    /** Memory budget, processing slots and connection permits SHARED with the HTTP listener. */
    private final IngressResources resources;
    /** Destination for finished events: the Logstash queue writer. May block when the queue is full. */
    private final Consumer<Map<String,Object>> sink;
    /** Rate-limited warning logger (never receives event payloads). */
    private final Consumer<String> diagnostic;
    /** Index applied to records that name none, and the optional allowlist (empty = unrestricted). */
    private final String defaultIndex;
    private final Set<String> indexes;
    /** Bound listening socket; a TLS server socket when the caller supplied a TLS-enabled config. */
    private final ServerSocket listener;
    /** Live connections and the virtual thread serving each; guarded by its own monitor. */
    private final Map<Socket,Thread> workers=new HashMap<>();
    /** One shared timer thread that closes sockets whose read/write deadline expired. */
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"s2s-tcp-deadlines");t.setDaemon(true);return t;});
    /** Time of the last diagnostic, to log at most one connection-failure warning per minute. */
    private final AtomicLong lastWarning=new AtomicLong();
    private final Thread acceptor;
    /** Set once by shutdown or a fatal accept error; workers re-check it between records. */
    private volatile boolean stopped;
    /** Fatal listener error (for example the server socket was closed unexpectedly). */
    private volatile IOException failure;

    S2STcpServer(String host,int port,TlsConfig tls,Limits limits,IngressResources resources,
                 Consumer<Map<String,Object>> sink,String defaultIndex,Set<String> indexes,Consumer<String> diagnostic)throws IOException{
        this.limits=limits;this.resources=resources;this.sink=sink;this.defaultIndex=defaultIndex;this.indexes=Set.copyOf(indexes);this.diagnostic=diagnostic;
        if(defaultIndex.isBlank())throw new IllegalArgumentException("TCP default index must not be blank");
        deadlines.setRemoveOnCancelPolicy(true);listener=tls.bind(host,port,limits.connections());
        acceptor=Thread.ofVirtual().name("s2s-tcp-accept").unstarted(this::accept);
    }
    /** Begin accepting connections (the socket is already bound by the constructor). */
    void start(){acceptor.start();}
    /** Actual bound port; useful when the configured port is 0 (tests). */
    int port(){return listener.getLocalPort();}
    /** Non-null when the listener died unexpectedly; the input then stops with an error. */
    IOException failure(){return failure;}
    /**
     * Accept loop. A connection permit is taken BEFORE a worker is created, so a
     * flood of idle or hostile connections is closed immediately once the shared
     * connection cap is reached instead of piling up threads.
     */
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
    /**
     * Arm a watchdog that closes the socket after the configured read time. Used
     * around every blocking socket operation; closing the socket makes the blocked
     * call fail, which is how slow-loris style peers are cut off. The caller MUST
     * cancel the returned future when the operation finishes in time.
     */
    private ScheduledFuture<?> deadline(Socket socket){
        return deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},limits.readMillis(),TimeUnit.MILLISECONDS);
    }
    /**
     * Serve one connection from handshake to close. Overall shape:
     * <ol>
     * <li>TLS handshake (if enabled) under a deadline;</li>
     * <li>greeting, capability exchange and ForwarderInfo (handshake phase, holds
     *     one shared processing slot so unauthenticated peers cannot occupy
     *     unlimited resources);</li>
     * <li>release the slot, then loop over compact records: for each record take a
     *     slot, read+map it, insert its events, send the ACK, release the slot.</li>
     * </ol>
     * Every failure path ends in the {@code finally} block, which cancels timers,
     * returns every permit exactly once and closes the socket.
     */
    private void handle(Socket socket){
        /** True while this worker holds a processing slot, so the finally block releases it exactly once. */
        boolean admitted=false;
        /** Currently armed I/O deadline, or null. */
        ScheduledFuture<?> io=null;
        /** The record stream: the raw input, or an inflating wrapper when the stream is compressed. */
        InputStream records=null;
        try(var header=resources.memory.lease();var infoMemory=resources.memory.lease()){
            // Reserve memory for the handshake up front so a connection flood cannot exceed the budget.
            header.charge(256L<<10);io=deadline(socket);socket.setSoTimeout(limits.readMillis());
            // Finish the TLS handshake now (inside the deadline) rather than lazily on first read.
            if(socket instanceof SSLSocket ssl)ssl.startHandshake();
            InputStream input=new BufferedInputStream(socket.getInputStream(),8192);OutputStream output=socket.getOutputStream();
            var greeting=S2STcpProtocol.greeting(input);
            // Only now, with a valid greeting, compete for a processing slot; a busy server says so by closing.
            if(!resources.processing.tryAcquire(limits.admissionMillis(),TimeUnit.MILLISECONDS))throw HecException.busy();admitted=true;
            boolean requestedAck,compressed;
            try(var capabilityMemory=resources.memory.lease()){
                var capabilities=S2STcpProtocol.frame(input,limits,capabilityMemory);
                String text=capabilities.pairs().get("__s2s_capabilities");
                if(text==null)throw new IOException("missing TCP capabilities");
                // The sender states whether it wants acknowledgements and whether it will compress.
                requestedAck=S2STcpProtocol.capability(text,"ack");compressed=S2STcpProtocol.capability(text,"compression");
                if(capabilities.compressed()&&!compressed)throw new IOException("inconsistent TCP compression request");
                // Our answer: v4 compact records only, no heartbeats/tokens/certificate requests.
                S2STcpProtocol.hello(output);
            }
            // ForwarderInfo: the sender confirms the v4 compact format and identifies itself by GUID.
            var info=S2STcpProtocol.frame(input,limits,infoMemory);
            if(!S2STcpProtocol.capability(info.pairs().get("__s2s_capabilities"),"v4"))throw new IOException("compact TCP v4 was not negotiated");
            String guid=info.pairs().get("_guid");
            if(guid==null||!guid.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IOException("missing/invalid sender GUID");
            guid=guid.toLowerCase(Locale.ROOT);
            // Connection-level provenance, copied into @metadata.splunk_hec.tcp of every event
            // from this connection when hec_metadata is "full".
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
            // TCP has no HEC token, so synthesize a "policy" for the shared event mapper: the default
            // index, the sender hostname as default host, and the configured index allowlist. The
            // identity is derived from the GUID only to namespace event IDs per sender.
            var policy=new TokenStore.Token("tcp:"+TokenStore.fingerprint(guid),false,
                Map.of("index",defaultIndex,"host",greeting.hostname()),indexes,false,false,false,600_000_000_000L);
            // Handshake done: give the slot back and drop the handshake deadline. From here on a
            // slot is taken per record, and an idle connection between records is legitimate.
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
            // The mapper turns decoded wire records into the native envelope; the session keeps the
            // per-connection dictionary of channels (source/host/sourcetype tuples) and the timezone.
            HecProtocol protocol=new HecProtocol(limits);S2SEvents mapper=new S2SEvents(limits,protocol,resources.metadata);
            try(var session=new S2SDecoder(limits).new StreamSession()){
                // The first byte of every record is its opcode (FE/F8 metadata, FC event, FD close, FF timezone).
                int opcode;
                while(!stopped&&(opcode=records.read())>=0){
                    // No detached writer or early ACK: a full queue keeps this
                    // owned worker blocked and stops reading further peer bytes.
                    resources.processing.acquire();admitted=true;
                    var memory=resources.memory.lease();boolean retained=false;
                    try{
                        if(stopped||Thread.currentThread().isInterrupted())throw HecException.busy();
                        // Reading the REST of a record must finish within the deadline even though
                        // waiting for the NEXT record's first byte has no deadline (idle is fine).
                        socket.setSoTimeout(limits.readMillis());io=deadline(socket);
                        // Metadata records return "retainsLease": their memory stays reserved while the
                        // channel exists and is released when the channel is replaced or closed.
                        var record=session.read(opcode,records,memory);retained=record.retainsLease();
                        io.cancel(false);io=null;socket.setSoTimeout(0);
                        // Metadata/control records produce no events. For an event record, build ALL envelopes
                        // first: if any of them is invalid nothing has been inserted yet.
                        List<Map<String,Object>> events=record.event()==null||record.event().control()?List.of():
                            mapper.mapWithIdentity(List.of(record.event()),policy,Map.of(),record.wireSha256(),memory);
                        for(var event:events){
                            // hec_metadata id_only/none attach no connection provenance, so skip building it.
                            if(resources.metadata!=MetadataMode.FULL)continue;
                            memory.charge(2048);
                            @SuppressWarnings("unchecked") var original=(Map<String,Object>)((Map<?,?>)event.get("@metadata")).get("splunk_hec");
                            Map<String,Object> metadata=new LinkedHashMap<>(original);
                            Map<String,Object> transport=new LinkedHashMap<>(connectionInfo);
                            if(record.eventId()!=null)transport.put("event_id",Long.toUnsignedString(record.eventId()));
                            metadata.put("tcp",transport);event.put("@metadata",Map.of("splunk_hec",metadata));
                            // The connection provenance counts toward the logical event-size cap too.
                            protocol.validateLogicalSize(event,memory);
                        }
                        // Insertion into the Logstash queue. This call may block for a long time when the queue
                        // is full; that is the intended back-pressure. An interrupt (shutdown) aborts it
                        // without an ACK, so the sender resends after restart.
                        for(var event:events){if(stopped||Thread.currentThread().isInterrupted())throw HecException.busy();sink.accept(event);}
                        // ACK only if the sender asked for acknowledgements and this record carried a real
                        // (non-zero) event ID. This line is reached strictly AFTER all inserts succeeded.
                        if(requestedAck&&record.eventId()!=null&&record.eventId()!=0){
                            // Latest peers' zero-ID terminal/heartbeat records have
                            // no reverse ACK in the real receiver captures.
                            io=deadline(socket);S2STcpProtocol.ack(output,record.eventId());io.cancel(false);io=null;
                        }
                    }finally{
                        // Per-record cleanup: stop the timer, free the record's memory (unless a channel
                        // keeps it) and give the processing slot back for other connections/HTTP requests.
                        if(io!=null){io.cancel(false);io=null;}
                        if(!retained)memory.close();resources.processing.release();admitted=false;
                    }
                }
            }
        }catch(Exception error){
            // Any exception ends THIS connection only (no ACK was sent for the failing record, so the
            // sender retries it). Log it at most once a minute, with the reason class and a hint, never
            // with event content. Ordinary peer closes/resets/timeouts are not diagnostics.
            if(!stopped&&!(error instanceof EOFException)&&!(error instanceof SocketException)){long now=System.currentTimeMillis(),before=lastWarning.get();if(now-before>=60000&&lastWarning.compareAndSet(before,now))diagnostic.accept("S2S TCP connection closed before further acceptance ("+error.getClass().getSimpleName()+(error instanceof HecException failure?": "+failure.getMessage()+"; queue/resource pressure, a malformed record or an event above s2s_tcp_max_event_bytes":
                error.getClass().getSimpleName().equals("QueueRuntimeException")?": "+String.valueOf(error.getMessage()).substring(0,Math.min(160,String.valueOf(error.getMessage()).length()))+"; the sender will retry. A persistent queue rejects events larger than queue.page_capacity":"")+")");}
        }finally{
            // Connection cleanup: runs for every exit path (normal close, error, shutdown).
            if(io!=null)io.cancel(false);
            if(admitted)resources.processing.release();
            if(records instanceof S2STcpProtocol.Inflated inflated)try{inflated.close();}catch(IOException ignored){}
            try{socket.close();}catch(IOException ignored){}
            synchronized(workers){workers.remove(socket);workers.notifyAll();}resources.connections.release();
        }
    }
    /** Stop accepting new connections; existing workers continue until told to stop. */
    private void stopAdmission(){stopped=true;try{listener.close();}catch(IOException ignored){}}
    /**
     * First phase of shutdown: refuse new connections, cancel timers, then close every client socket and
     * interrupt its worker so blocked reads and blocked queue writes both end promptly. The input calls
     * this on BOTH listeners before joining either, so total shutdown time is one grace period, not two.
     */
    void beginStop(){
        stopAdmission();deadlines.shutdownNow();
        synchronized(workers){for(var entry:workers.entrySet()){try{entry.getKey().close();}catch(IOException ignored){}entry.getValue().interrupt();}}
    }
    @Override public void close(){closeBy(System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(limits.shutdownMillis()));}
    /**
     * Second phase of shutdown: JOIN every worker and the acceptor until {@code deadline}. A worker that is
     * still alive afterwards is reported as an error rather than silently abandoned, because an orphaned
     * worker could keep writing events into a queue that Logstash believes is closed.
     */
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
