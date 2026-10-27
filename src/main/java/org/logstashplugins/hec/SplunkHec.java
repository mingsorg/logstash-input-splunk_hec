package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Logstash Java Input adapter for one shared HEC listener. Each configured
 * splunk_hec block owns one server, token snapshot registry and ACK/state store;
 * HecServer registers all event/raw/S2S routes for that listener.
 *
 * <p>The Consumer supplied to start is Logstash's queue-writing boundary. The
 * server passes native Maps to it; Logstash constructs its Event representation
 * and supplies required internals. This adapter does not select an Elasticsearch
 * index or call a destination: filters and outputs run later in the pipeline.
 * Runtime-version enforcement also occurs in the Ruby loader, independently of
 * the reusable Java plugin API version.
 */
@LogstashPlugin(name="splunk_hec")
public final class SplunkHec implements Input {
    private static final PluginConfigSpec<String> HOST=PluginConfigSpec.stringSetting("host","0.0.0.0");
    private static final PluginConfigSpec<Long> PORT=PluginConfigSpec.numSetting("port",8088);
    private static final PluginConfigSpec<Password> TOKENS=PluginConfigSpec.passwordSetting("tokens_json","[]",false,false);
    private static final PluginConfigSpec<String> FILE=PluginConfigSpec.stringSetting("inputs_conf","");
    private static final PluginConfigSpec<String> STATE=PluginConfigSpec.stringSetting("state_directory","data/splunk_hec");
    private static final PluginConfigSpec<Boolean> TLS=PluginConfigSpec.booleanSetting("ssl_enabled",true);
    private static final PluginConfigSpec<String> SANS=PluginConfigSpec.stringSetting("ssl_self_signed_sans","dns:localhost,ip:127.0.0.1,ip:::1");
    private static final PluginConfigSpec<String> STORE=PluginConfigSpec.stringSetting("ssl_keystore","");
    private static final PluginConfigSpec<String> STORETYPE=PluginConfigSpec.stringSetting("ssl_keystore_type","PKCS12");
    private static final PluginConfigSpec<Password> PASSWORD=PluginConfigSpec.passwordSetting("ssl_keystore_password","",false,false);
    private static final PluginConfigSpec<String> CERT=PluginConfigSpec.stringSetting("ssl_certificate","");
    private static final PluginConfigSpec<String> KEY=PluginConfigSpec.stringSetting("ssl_key","");
    private static final PluginConfigSpec<String> CA=PluginConfigSpec.stringSetting("ssl_client_ca","");
    private static final PluginConfigSpec<Boolean> MTLS=PluginConfigSpec.booleanSetting("ssl_client_authentication",false);
    private static final Map<String,Long> DEFAULTS=Map.ofEntries(Map.entry("max_concurrent_requests",16L),Map.entry("max_connections",64L),
        Map.entry("max_wire_bytes",10L<<20),Map.entry("max_expanded_bytes",64L<<20),Map.entry("max_inflight_bytes",128L<<20),
        Map.entry("max_event_bytes",1L<<20),Map.entry("max_events",10_000L),Map.entry("max_json_depth",100L),
        Map.entry("body_read_timeout_ms",30_000L),Map.entry("admission_timeout_ms",1_000L),Map.entry("shutdown_grace_ms",10_000L));
    private static final Map<String,PluginConfigSpec<Long>> NUMBERS=new LinkedHashMap<>();
    static{DEFAULTS.forEach((k,v)->NUMBERS.put(k,PluginConfigSpec.numSetting(k,v)));}
    private final String id,host;
    private final int port;
    private final Limits limits;
    private final TokenStore tokens;
    private final TlsConfig tls;
    private final AckManager acks;
    private final CountDownLatch done=new CountDownLatch(1);
    private volatile HecServer server;
    private boolean stopped;
    private volatile RuntimeException stopFailure;
    private final ScheduledExecutorService reload=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"hec-policy-reload");t.setDaemon(true);return t;});

    public SplunkHec(String id,Configuration config,Context context)throws Exception{
        this.id=id;host=config.get(HOST);long p=config.get(PORT);
        if(p<1||p>65535)throw new IllegalArgumentException("port must be 1..65535");port=(int)p;
        limits=new Limits(n(config,"max_concurrent_requests"),n(config,"max_connections"),n(config,"max_wire_bytes"),
            n(config,"max_expanded_bytes"),config.get(NUMBERS.get("max_inflight_bytes")),n(config,"max_event_bytes"),
            n(config,"max_events"),n(config,"max_json_depth"),n(config,"body_read_timeout_ms"),n(config,"admission_timeout_ms"),n(config,"shutdown_grace_ms"));
        Path state=Path.of(config.get(STATE)).toAbsolutePath();
        tokens=new TokenStore(path(config.get(FILE)),config.get(TOKENS).getValue(),message->context.getLogger(this).warn(message));
        tls=new TlsConfig(new TlsConfig.Options(config.get(TLS),state.resolve("identity"),config.get(SANS),path(config.get(STORE)),
            config.get(STORETYPE),config.get(PASSWORD).getValue(),path(config.get(CERT)),path(config.get(KEY)),path(config.get(CA)),config.get(MTLS)));
        acks=new AckManager(state);
        if(!config.get(FILE).isEmpty())reload.scheduleWithFixedDelay(tokens::reload,1,1,TimeUnit.SECONDS);
    }
    private static int n(Configuration config,String name){return Math.toIntExact(config.get(NUMBERS.get(name)));}
    private static Path path(String s){return s.isEmpty()?null:Path.of(s);}
    @Override public void start(Consumer<Map<String,Object>> consumer){
        try{
            // One dispatcher serves every supported path. The consumer is shared
            // by concurrent requests, so cross-request insertion order can interleave.
            synchronized(this){if(stopped)return;server=new HecServer(host,port,tls,limits,tokens,acks,consumer);server.start();}
            synchronized(this){while(!stopped){
                if(server.failure()!=null)throw new IllegalStateException("HEC listener failed",server.failure());
                wait(250);
            }}
        }catch(InterruptedException e){Thread.currentThread().interrupt();}
        catch(Exception e){throw new IllegalStateException("HEC input failed",e);}
        finally{
            try{stop();}finally{done.countDown();}
        }
    }
    @Override public synchronized void stop(){
        HecServer closing;
        if(stopped)return;stopped=true;closing=server;notifyAll();
        boolean interrupted=Thread.interrupted();
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(limits.shutdownMillis());
        reload.shutdownNow();
        try{
            if(closing!=null)closing.closeBy(deadline);
            interrupted|=Thread.interrupted();
            while(!reload.isTerminated()){
                long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException("policy reload did not terminate");
                try{reload.awaitTermination(left,TimeUnit.NANOSECONDS);}
                catch(InterruptedException stopInterrupt){interrupted=true;}
            }
            acks.close();
        }catch(java.io.IOException e){stopFailure=new IllegalStateException("ACK state close failed",e);throw stopFailure;}
        catch(RuntimeException e){stopFailure=e;throw e;}
        finally{done.countDown();if(interrupted)Thread.currentThread().interrupt();}
    }
    @Override public void awaitStop()throws InterruptedException{done.await();if(stopFailure!=null)throw stopFailure;}
    @Override public String getId(){return id;}
    @Override public Collection<PluginConfigSpec<?>> configSchema(){
        // Listener/TLS/policy/limits are common to all routes. Payload format is
        // defined by HecServer's path dispatch, not an input-wide JSON codec.
        List<PluginConfigSpec<?>> schema=new ArrayList<>(List.of(HOST,PORT,TOKENS,FILE,STATE,TLS,SANS,STORE,STORETYPE,PASSWORD,CERT,KEY,CA,MTLS));
        schema.addAll(NUMBERS.values());return schema;
    }
}
