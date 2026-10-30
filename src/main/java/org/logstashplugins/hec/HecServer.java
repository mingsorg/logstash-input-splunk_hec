package org.logstashplugins.hec;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * One HTTPS listener serves event, raw and binary S2S HTTP requests concurrently.
 * The URL path selects the grammar; Content-Type does not auto-detect a format.
 * Token policy, admission slots, memory and the downstream queue are shared.
 *
 * <p>Processing order: TLS/HTTP framing, authentication/admission, body decoding,
 * complete request preparation, queue insertion, then a HEC response. This server
 * uses one HTTP/1.1 request per connection with Connection: close. Parallelism is
 * across bounded connections, including unauthenticated TLS/idle peers.
 * See {@code docs/http-endpoints.md} for the complete route/payload contract.
 */
public final class HecServer implements AutoCloseable {
    private final Limits limits;
    private final TokenStore tokens;
    private final AckManager acks;
    private final Consumer<Map<String,Object>> sink;
    private final HecProtocol protocol;
    private final MemoryBudget memory;
    private final IngressResources resources;
    private final boolean ownsResources;
    private final Semaphore emergencyHealth;
    private final Semaphore processing,connections;
    private final ServerSocket listener;
    private final Map<Socket,Thread> workers=new HashMap<>();
    private volatile boolean stopped;
    private volatile IOException acceptFailure;
    private final Thread acceptor;
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"hec-io-deadlines");t.setDaemon(true);return t;});
    private record Request(String method,String path,Map<String,String> query,Map<String,String> headers){}

    public HecServer(String host,int port,TlsConfig tls,Limits limits,TokenStore tokens,AckManager acks,Consumer<Map<String,Object>> sink)throws IOException{
        this(host,port,tls,limits,tokens,acks,sink,new IngressResources(limits),true);
    }
    HecServer(String host,int port,TlsConfig tls,Limits limits,TokenStore tokens,AckManager acks,Consumer<Map<String,Object>> sink,IngressResources resources)throws IOException{
        this(host,port,tls,limits,tokens,acks,sink,resources,false);
    }
    private HecServer(String host,int port,TlsConfig tls,Limits limits,TokenStore tokens,AckManager acks,Consumer<Map<String,Object>> sink,IngressResources resources,boolean ownsResources)throws IOException{
        this.limits=limits;this.tokens=tokens;this.acks=acks;this.sink=sink;
        this.resources=resources;this.ownsResources=ownsResources;
        protocol=new HecProtocol(limits);memory=resources.memory;emergencyHealth=resources.emergencyHealth;
        deadlines.setRemoveOnCancelPolicy(true);
        processing=resources.processing;connections=resources.connections;
        listener=tls.bind(host,port,limits.connections());
        acceptor=Thread.ofVirtual().name("hec-accept").unstarted(this::accept);
    }
    public void start(){acceptor.start();}
    public int port(){return listener.getLocalPort();}
    IOException failure(){return acceptFailure;}
    private void accept(){
        while(!stopped)try{
            Socket socket=listener.accept();
            if(!connections.tryAcquire()){socket.close();continue;}
            synchronized(workers){
                if(stopped){socket.close();connections.release();continue;}
                Thread worker=Thread.ofVirtual().name("hec-request").unstarted(()->handle(socket));
                workers.put(socket,worker);worker.start();
            }
        }catch(IOException e){if(!stopped){acceptFailure=e;stopAdmission();}}
    }
    private void handle(Socket socket){
        boolean admitted=false, healthOnly=false;
        ScheduledFuture<?> readDeadline=null;
        MemoryBudget.Lease lease=memory.lease();
        try{
            try { lease.charge(256L<<10); }
            catch(HecException unavailable){
                // One pre-reserved, bounded header/TLS allowance remains usable
                // for health when admitted requests consume the shared budget.
                if(!emergencyHealth.tryAcquire())throw unavailable;
                healthOnly=true;
            }
            readDeadline=deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},limits.readMillis(),TimeUnit.MILLISECONDS);
            long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(limits.readMillis());
            socket.setSoTimeout(limits.readMillis());
            if(socket instanceof SSLSocket ssl)ssl.startHandshake();
            InputStream input=socket.getInputStream();
            Request request=headers(socket,input,deadline);
            String kind=route(request.path);
            if(!request.method.equals(kind.equals("health")?"GET":"POST"))throw new HecException(405,404,"The requested URL was not found on this server.");
            if(kind.equals("health")){
                boolean healthy=!healthOnly && !stopped && processing.availablePermits()>0 && memory.used()<limits.aggregate();
                respond(socket,healthy?200:503,Map.of("text",healthy?"HEC is healthy":"HEC is unhealthy","code",healthy?17:18));return;
            }
            if(healthOnly)throw HecException.busy();
            tokens.authenticate(request.headers.get("authorization"),request.query.get("token"));
            if(!processing.tryAcquire(limits.admissionMillis(),TimeUnit.MILLISECONDS))throw HecException.busy();
            admitted=true;
            if(stopped)throw HecException.busy();
            // Re-authenticate after waiting: revocation while queued for admission
            // must apply. Once admitted, this immutable policy covers the request.
            TokenStore.Token policy=tokens.authenticate(request.headers.get("authorization"),request.query.get("token"));
            String channel=null;
            // This is the HTTP GUID channel for HEC ACKs, not the arbitrary S2S
            // metadata-tuple channel contained inside a binary body.
            if(policy.ack())channel=channel(request);
            if(kind.equals("ack")&&!policy.ack())throw new HecException(400,14,"ACK is disabled");
            String expectation=request.headers.get("expect");
            if(expectation!=null){
                if(!expectation.equalsIgnoreCase("100-continue"))throw new HecException(417,6,"Invalid data format");
                OutputStream output=socket.getOutputStream();
                output.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.US_ASCII));output.flush();
            }
            {
                byte[] body=body(socket,input,request.headers,deadline,lease);
                readDeadline.cancel(false);
                // Optional HTTP gzip wraps the selected format. A gzip-wrapped
                // S2S request still contains F9 + zlib after this first expansion.
                Compression.Expansion expansion=new Compression.Expansion(limits.expanded(),lease);
                String encoding=request.headers.getOrDefault("content-encoding","identity");
                if(encoding.equalsIgnoreCase("gzip"))body=Compression.gzip(body,expansion);
                else if(!encoding.equalsIgnoreCase("identity"))throw HecException.invalid();
                if(kind.equals("ack")){
                    respond(socket,200,Map.of("acks",acks.poll(policy,channel,protocol.acknowledgments(body,lease))));return;
                }
                // Dispatch is explicit, not sniffed from MIME type or body bytes:
                // /event -> JSON envelopes; /raw -> UTF-8 lines; /s2s -> binary
                // records then native envelopes. S2S must finish ALL validation
                // before any of its records can reach the queue insertion loop.
                HecProtocol.Prepared prepared;
                if(kind.equals("s2s")){
                    List<S2SDecoder.Event> records=new S2SDecoder(limits).decode(body,expansion,lease);
                    prepared=new HecProtocol.Prepared(new S2SEvents(limits,protocol,resources.metadata,resources.metadataFields).map(records,policy,request.query,body,lease),null);
                }else if(kind.equals("raw"))prepared=protocol.raw(body,policy,request.query,lease);
                else prepared=protocol.events(body,policy,request.query,lease);
                // Reserve ACK capacity before irreversible insertion. Event parsing
                // may return a valid prefix plus an error; a failed request must
                // never complete that ticket or return a success ackId.
                AckManager.Ticket ticket=policy.ack()&&(prepared.failure()==null||!prepared.events().isEmpty())?acks.reserve(policy,channel):null;
                boolean success=false;
                try{
                    for(Map<String,Object> event:prepared.events()){
                        if(stopped||Thread.currentThread().isInterrupted())throw HecException.busy();
                        // No detached task: this is the worker we interrupt and join at stop.
                        sink.accept(event);
                    }
                    if(prepared.failure()!=null)throw prepared.failure();
                    success=true;
                }finally{if(ticket!=null)acks.finish(ticket,success);}
                // Reaching here means all insertions returned. This is QUEUE
                // acceptance, not Elasticsearch/Splunk indexing or PQ fsync proof.
                Map<String,Object> response=new LinkedHashMap<>();response.put("text","Success");response.put("code",0);
                if(ticket!=null)response.put("ackId",ticket.id());
                respond(socket,200,response);
            }
        }catch(HecException e){quietResponse(socket,e.status,e.response());}
        catch(InterruptedException e){Thread.currentThread().interrupt();quietResponse(socket,503,HecException.busy().response());}
        catch(Exception e){quietResponse(socket,503,HecException.busy().response());}
        finally{
            if(readDeadline!=null)readDeadline.cancel(false);
            lease.close();
            if(healthOnly)emergencyHealth.release();
            try{socket.close();}catch(IOException ignored){}
            if(admitted)processing.release();
            synchronized(workers){workers.remove(socket);workers.notifyAll();}
            connections.release();
        }
    }
    /** Exact observed routes/aliases; trailing slashes and collector/1.0 are not aliases. */
    static String route(String path){
        if(path.equals("/services/collector"))return "event";
        for(String kind:List.of("event","raw","s2s","ack","health"))
            if(path.equals("/services/collector/"+kind)||path.equals("/services/collector/"+kind+"/1.0"))return kind;
        throw new HecException(404,404,"The requested URL was not found on this server.");
    }
    private static String channel(Request request){
        String channel=request.headers.get("x-splunk-request-channel");
        if(channel==null||channel.isEmpty())channel=request.query.get("channel");
        if(channel==null||channel.isEmpty())throw new HecException(400,10,"Data channel is missing");
        if(!channel.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new HecException(400,11,"Invalid data channel");
        return channel.toLowerCase(Locale.ROOT);
    }
    private Request headers(Socket socket,InputStream input,long deadline)throws IOException{
        int[] remaining={32768};String first=line(socket,input,deadline,remaining);
        String[] parts=first.split(" ",-1);if(parts.length!=3||!parts[2].equals("HTTP/1.1"))throw HecException.invalid();
        URI uri;try{uri=URI.create(parts[1]);}catch(IllegalArgumentException e){throw HecException.invalid();}
        if(uri.isAbsolute()||uri.getRawFragment()!=null)throw HecException.invalid();
        Map<String,String> headers=new HashMap<>();String s;
        while(!(s=line(socket,input,deadline,remaining)).isEmpty()){
            int colon=s.indexOf(':');if(colon<=0)throw HecException.invalid();
            String name=s.substring(0,colon).toLowerCase(Locale.ROOT);
            if(!name.matches("[a-z0-9!#$%&'*+.^_`|~-]+"))throw HecException.invalid();
            if(headers.putIfAbsent(name,s.substring(colon+1).strip())!=null)throw HecException.invalid();
        }
        Map<String,String> query=new HashMap<>();
        if(uri.getRawQuery()!=null)for(String item:uri.getRawQuery().split("&")){
            String[] pair=item.split("=",2);
            try{
                String key=queryComponent(pair[0]);
                String value=pair.length==2?queryComponent(pair[1]):"";
                if(query.putIfAbsent(key,value)!=null)throw HecException.invalid();
            }catch(IllegalArgumentException e){throw HecException.invalid();}
        }
        return new Request(parts[0],uri.getRawPath(),query,headers);
    }
    private static String queryComponent(String component){
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        for(int i=0;i<component.length();i++){
            char c=component.charAt(i);
            if(c=='%'){
                if(i+2>=component.length())throw HecException.invalid();
                int high=Character.digit(component.charAt(++i),16),low=Character.digit(component.charAt(++i),16);
                if(high<0||low<0)throw HecException.invalid();out.write(high*16+low);
            }else{if(c>127)throw HecException.invalid();out.write(c=='+'?' ':c);}
        }
        return HecProtocol.utf8(out.toByteArray());
    }
    private static String line(Socket socket,InputStream in,long deadline,int[] remaining)throws IOException{
        ByteArrayOutputStream line=new ByteArrayOutputStream();int last=-1;
        for(;;){
            if(--remaining[0]<0)throw HecException.invalid();
            timeout(socket,deadline);int c=in.read();if(c<0)throw HecException.invalid();
            if(c=='\n'){if(last!='\r')throw HecException.invalid();byte[] b=line.toByteArray();return new String(b,0,b.length-1,StandardCharsets.US_ASCII);}
            if(c<32&&c!='\r'&&c!='\t')throw HecException.invalid();line.write(c);last=c;
        }
    }
    private byte[] body(Socket socket,InputStream in,Map<String,String> headers,long deadline,MemoryBudget.Lease lease)throws IOException{
        String length=headers.get("content-length"),transfer=headers.get("transfer-encoding");
        if(length!=null&&transfer!=null)throw HecException.invalid();
        // Reserve growth/copies before each allocation, including chunked requests.
        lease.charge(16384);
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        byte[] scratch=new byte[8192];
        if(transfer!=null){
            if(!transfer.equalsIgnoreCase("chunked"))throw HecException.invalid();
            int[] framing={32768};
            for(;;){
                String chunk=line(socket,in,deadline,framing);int semi=chunk.indexOf(';');if(semi>=0)chunk=chunk.substring(0,semi);
                long n;try{if(!chunk.matches("[0-9A-Fa-f]{1,8}"))throw HecException.invalid();n=Long.parseLong(chunk,16);}catch(NumberFormatException e){throw HecException.invalid();}
                if(n==0){if(!line(socket,in,deadline,framing).isEmpty())throw HecException.invalid();break;}
                if(n>limits.wire()-out.size())throw HecException.busy();
                lease.charge(3L*n);
                read(socket,in,deadline,out,scratch,(int)n);
                if(!line(socket,in,deadline,framing).isEmpty())throw HecException.invalid();
            }
        }else{
            long n=0;if(length!=null)try{if(!length.matches("[0-9]+"))throw HecException.invalid();n=Long.parseLong(length);}catch(NumberFormatException e){throw HecException.invalid();}
            if(n>limits.wire())throw HecException.busy();
            lease.charge(3L*n);
            read(socket,in,deadline,out,scratch,(int)n);
        }
        return out.toByteArray();
    }
    private static void read(Socket socket,InputStream in,long deadline,ByteArrayOutputStream out,byte[] scratch,int count)throws IOException{
        while(count>0){timeout(socket,deadline);int n=in.read(scratch,0,Math.min(count,scratch.length));if(n<=0)throw HecException.invalid();out.write(scratch,0,n);count-=n;}
    }
    private static void timeout(Socket socket,long deadline)throws IOException{
        long remaining=deadline-System.nanoTime();if(remaining<=0)throw new SocketTimeoutException("body deadline");
        socket.setSoTimeout((int)Math.max(1,Math.min(Integer.MAX_VALUE,TimeUnit.NANOSECONDS.toMillis(remaining))));
    }
    private void respond(Socket socket,int status,Map<String,?> object)throws IOException{
        ScheduledFuture<?> writeDeadline;
        try{writeDeadline=deadlines.schedule(()->{try{socket.close();}catch(IOException ignored){}},limits.readMillis(),TimeUnit.MILLISECONDS);}
        catch(RejectedExecutionException stopped){throw new IOException("HEC server stopping",stopped);}
        try{
        byte[] body=HecProtocol.JSON.writeValueAsBytes(object);
        String header="HTTP/1.1 "+status+" "+(status==200?"OK":"Error")+"\r\nContent-Type: application/json; charset=UTF-8\r\nX-Content-Type-Options: nosniff\r\nVary: Authorization\r\nX-Frame-Options: SAMEORIGIN\r\nConnection: close\r\nContent-Length: "+body.length+"\r\n\r\n";
        OutputStream out=socket.getOutputStream();out.write(header.getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();
        }finally{writeDeadline.cancel(false);}
    }
    private void quietResponse(Socket socket,int status,Map<String,?> body){try{respond(socket,status,body);}catch(IOException ignored){}finally{try{socket.close();}catch(IOException ignored){}}}
    private void stopAdmission(){stopped=true;try{listener.close();}catch(IOException ignored){}}
    void beginStop(){
        stopAdmission();deadlines.shutdownNow();
        synchronized(workers){for(var entry:workers.entrySet()){
            try{entry.getKey().close();}catch(IOException ignored){}entry.getValue().interrupt();
        }}
    }
    @Override public void close(){closeBy(System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(limits.shutdownMillis()));}
    void closeBy(long deadline){
        boolean interrupted=Thread.interrupted();
        try{
        beginStop();
        deadlines.shutdownNow();
        List<Thread> joining;
        synchronized(workers){
            joining=new ArrayList<>(workers.values());
            for(var entry:workers.entrySet()){
                try{entry.getKey().close();}catch(IOException ignored){}
                entry.getValue().interrupt();
            }
        }
        joining.add(acceptor);
        for(Thread thread:joining)while(thread.isAlive()){
            long left=deadline-System.nanoTime();if(left<=0)break;
            try{thread.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(left)));}
            catch(InterruptedException stopInterrupt){interrupted=true;}
        }
        if(joining.stream().anyMatch(Thread::isAlive))throw new IllegalStateException("HEC shutdown deadline exceeded; queue worker still owned");
        while(!deadlines.isTerminated()){
            long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException("IO deadlines did not terminate");
            try{deadlines.awaitTermination(left,TimeUnit.NANOSECONDS);}
            catch(InterruptedException stopInterrupt){interrupted=true;}
        }
        if(ownsResources)resources.close();
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
}
