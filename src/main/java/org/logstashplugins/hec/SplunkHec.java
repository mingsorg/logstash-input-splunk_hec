package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Logstash Java Input adapter for one shared HEC listener. Each configured
 * splunk_hec block owns an HTTP server, optional cooked TCP server, shared resource
 * limits, token registry and ACK/state store. HecServer registers all HTTP routes;
 * TCP uses transport trust rather than HTTP token authentication.
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
    // =====================================================================================
    // Configuration options. Every option is documented, with defaults and constraints, in
    // docs/configuration.md; a unit test fails if one is added here without being documented.
    // =====================================================================================

    // ---- listener and state -------------------------------------------------------------
    /** Bind address for BOTH listeners. It is not a certificate identity. */
    private static final PluginConfigSpec<String> HOST=PluginConfigSpec.stringSetting("host","0.0.0.0");
    /** HTTP(S) listener port for HEC event/raw/S2S-over-HTTP/ack/health. */
    private static final PluginConfigSpec<Long> PORT=PluginConfigSpec.numSetting("port",8088);
    /** Inline token policy as a JSON array. A password-typed setting so Logstash never logs it. */
    private static final PluginConfigSpec<Password> TOKENS=PluginConfigSpec.passwordSetting("tokens_json","[]",false,false);
    /** Optional path to a Splunk-style inputs.conf holding token stanzas; reloaded every second. */
    private static final PluginConfigSpec<String> FILE=PluginConfigSpec.stringSetting("inputs_conf","");
    /** Persistent directory for the ACK counter lock and the generated TLS identity. One per input. */
    private static final PluginConfigSpec<String> STATE=PluginConfigSpec.stringSetting("state_directory","data/splunk_hec");

    // ---- TLS: switches are per listener, certificate material is shared -----------------
    // The HTTP listener defaults to TLS ON. The classic TCP listener defaults to plaintext (like a
    // stock Splunk 9997 receiver) because that is what most forwarders are configured for; it can be
    // switched to TLS independently. Either listener can use either setting.
    /** TLS for the HTTP listener (default on). */
    private static final PluginConfigSpec<Boolean> TLS=PluginConfigSpec.booleanSetting("ssl_enabled",true);
    /** Require a client certificate on the HTTP listener (mTLS). Needs ssl_client_ca. */
    private static final PluginConfigSpec<Boolean> MTLS=PluginConfigSpec.booleanSetting("ssl_client_authentication",false);
    /** TLS for the TCP listener (default off). Only relevant when s2s_tcp_enabled is true. */
    private static final PluginConfigSpec<Boolean> TCPTLS=PluginConfigSpec.booleanSetting("s2s_tcp_ssl_enabled",false);
    /** Require a client certificate on the TCP listener (mTLS). Needs s2s_tcp_ssl_enabled and ssl_client_ca. */
    private static final PluginConfigSpec<Boolean> TCPMTLS=PluginConfigSpec.booleanSetting("s2s_tcp_ssl_client_authentication",false);
    /** Subject alternative names written into a GENERATED certificate (keytool syntax). Used once. */
    private static final PluginConfigSpec<String> SANS=PluginConfigSpec.stringSetting("ssl_self_signed_sans","dns:localhost,ip:127.0.0.1,ip:::1");
    /** Your own PKCS12/JKS identity; exclusive with ssl_certificate/ssl_key. */
    private static final PluginConfigSpec<String> STORE=PluginConfigSpec.stringSetting("ssl_keystore","");
    private static final PluginConfigSpec<String> STORETYPE=PluginConfigSpec.stringSetting("ssl_keystore_type","PKCS12");
    private static final PluginConfigSpec<Password> PASSWORD=PluginConfigSpec.passwordSetting("ssl_keystore_password","",false,false);
    /** PEM certificate chain and unencrypted PKCS8 key, as an alternative to a keystore. */
    private static final PluginConfigSpec<String> CERT=PluginConfigSpec.stringSetting("ssl_certificate","");
    private static final PluginConfigSpec<String> KEY=PluginConfigSpec.stringSetting("ssl_key","");
    /** PEM bundle of client CAs/certificates trusted when client authentication is on. */
    private static final PluginConfigSpec<String> CA=PluginConfigSpec.stringSetting("ssl_client_ca","");

    // ---- event provenance ---------------------------------------------------------------
    /**
     * How much provenance is attached under {@code @metadata.splunk_hec}: "full" (default), "id_only"
     * (just the stable event id, enough for idempotent outputs) or "none". {@code @metadata} is not
     * written by outputs unless a filter copies it. {@code @timestamp} and {@code @version} are added by
     * Logstash itself and are not affected.
     */
    private static final PluginConfigSpec<String> METADATA=PluginConfigSpec.stringSetting("hec_metadata","full");
    /**
     * Exact decoded S2S per-record key -> simple destination name inside searchable s2s_metadata.
     * Empty by default. Applies to HTTP and TCP even with hec_metadata=none; values remain strings.
     * This does not select indexed fields, handshake provenance, or change coordinate-based IDs.
     * Strictly parsed once at startup; invalid policies fail without echoing configured values.
     */
    private static final PluginConfigSpec<String> S2SMETADATA=PluginConfigSpec.stringSetting("s2s_metadata_fields_json","{}");

    // ---- optional classic TCP listener ---------------------------------------------------
    /** Start the cooked-mode tcpout receiver (default off). */
    private static final PluginConfigSpec<Boolean> TCP=PluginConfigSpec.booleanSetting("s2s_tcp_enabled",false);
    /** TCP port (default 9997); must differ from the HTTP port. */
    private static final PluginConfigSpec<Long> TCPPORT=PluginConfigSpec.numSetting("s2s_tcp_port",9997);
    /** Index for records that name none (TCP has no token to supply one). */
    private static final PluginConfigSpec<String> TCPINDEX=PluginConfigSpec.stringSetting("s2s_tcp_default_index","main");
    /** Optional comma-separated allowlist of indexes TCP records may target; empty means any. */
    private static final PluginConfigSpec<String> TCPINDEXES=PluginConfigSpec.stringSetting("s2s_tcp_indexes","");
    // 0 = automatic. Real latest heavy forwarders send internal records above 1 MiB; refusing
    // such a record would make the sender retry it forever and block its queue.
    private static final PluginConfigSpec<Long> TCPEVENT=PluginConfigSpec.numSetting("s2s_tcp_max_event_bytes",0);

    // ---- shared resource limits (names and defaults documented in docs/configuration.md 3.5) ----
    private static final Map<String,Long> DEFAULTS=Map.ofEntries(Map.entry("max_concurrent_requests",16L),Map.entry("max_connections",64L),
        Map.entry("max_wire_bytes",10L<<20),Map.entry("max_expanded_bytes",64L<<20),Map.entry("max_inflight_bytes",128L<<20),
        Map.entry("max_event_bytes",1L<<20),Map.entry("max_events",10_000L),Map.entry("max_json_depth",100L),
        Map.entry("body_read_timeout_ms",30_000L),Map.entry("admission_timeout_ms",1_000L),Map.entry("shutdown_grace_ms",10_000L));
    private static final Map<String,PluginConfigSpec<Long>> NUMBERS=new LinkedHashMap<>();
    static{DEFAULTS.forEach((k,v)->NUMBERS.put(k,PluginConfigSpec.numSetting(k,v)));}
    private final String id,host;
    private final int port;
    private final boolean tcpEnabled;
    private final int tcpPort;
    private final String tcpIndex;
    private final Set<String> tcpIndexes;
    private final Limits tcpLimits;
    private final Consumer<String> diagnostic;
    private final IngressResources resources;
    private final Limits limits;
    private final TokenStore tokens;
    private final TlsConfig tls,tcpTls;
    private final boolean httpTlsEnabled,tcpTlsEnabled;
    private final AckManager acks;
    private final CountDownLatch done=new CountDownLatch(1);
    private volatile HecServer server;
    private volatile S2STcpServer tcpServer;
    private boolean stopped;
    private volatile RuntimeException stopFailure;
    private final ScheduledExecutorService reload=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"hec-policy-reload");t.setDaemon(true);return t;});

    public SplunkHec(String id,Configuration config,Context context)throws Exception{
        this.id=id;host=config.get(HOST);long p=config.get(PORT);
        if(p<1||p>65535)throw new IllegalArgumentException("port must be 1..65535");port=(int)p;
        tcpEnabled=config.get(TCP);long tp=config.get(TCPPORT);
        if(tp<1||tp>65535||tcpEnabled&&tp==p)throw new IllegalArgumentException("S2S TCP port must be distinct and within 1..65535");tcpPort=(int)tp;
        tcpIndex=config.get(TCPINDEX);if(tcpIndex.isBlank())throw new IllegalArgumentException("TCP default index must not be blank");
        Set<String> allowed=new HashSet<>();String configured=config.get(TCPINDEXES);
        if(!configured.isBlank())for(String index:configured.split(",",-1)){
            if(index.isBlank())throw new IllegalArgumentException("empty TCP allowed index");allowed.add(index.strip());
        }
        if(!allowed.isEmpty()&&!allowed.contains(tcpIndex))throw new IllegalArgumentException("TCP default index must be allowed");
        tcpIndexes=Set.copyOf(allowed);diagnostic=message->context.getLogger(this).warn(message);
        limits=new Limits(n(config,"max_concurrent_requests"),n(config,"max_connections"),n(config,"max_wire_bytes"),
            n(config,"max_expanded_bytes"),config.get(NUMBERS.get("max_inflight_bytes")),n(config,"max_event_bytes"),
            n(config,"max_events"),n(config,"max_json_depth"),n(config,"body_read_timeout_ms"),n(config,"admission_timeout_ms"),n(config,"shutdown_grace_ms"));
        long tcpEvent=config.get(TCPEVENT);
        if(tcpEvent<0)throw new IllegalArgumentException("s2s_tcp_max_event_bytes must not be negative");
        if(tcpEvent==0)tcpEvent=Math.max(limits.event(),Math.min(8L<<20,limits.expanded()));
        if(tcpEvent>limits.expanded())throw new IllegalArgumentException("s2s_tcp_max_event_bytes must not exceed max_expanded_bytes");
        tcpLimits=new Limits(limits.concurrency(),limits.connections(),limits.wire(),limits.expanded(),limits.aggregate(),(int)tcpEvent,
            limits.events(),limits.depth(),limits.readMillis(),limits.admissionMillis(),limits.shutdownMillis());
        resources=new IngressResources(limits,MetadataMode.parse(config.get(METADATA)),S2SMetadataFields.parse(config.get(S2SMETADATA)));
        Path state=Path.of(config.get(STATE)).toAbsolutePath();
        tokens=new TokenStore(path(config.get(FILE)),config.get(TOKENS).getValue(),message->context.getLogger(this).warn(message));
        // --- Per-listener TLS -------------------------------------------------------------------------
        // HEC (HTTP) defaults to TLS on; the classic TCP listener defaults to plaintext (like a stock
        // Splunk 9997 receiver) but can be switched to TLS. The TCP TLS switch only matters when the TCP
        // listener itself is enabled.
        httpTlsEnabled=config.get(TLS);tcpTlsEnabled=tcpEnabled&&config.get(TCPTLS);
        boolean httpClientAuth=config.get(MTLS),tcpClientAuth=config.get(TCPMTLS);
        Path keystore=path(config.get(STORE)),certificate=path(config.get(CERT)),key=path(config.get(KEY)),clientCa=path(config.get(CA));
        // Client-certificate authentication only makes sense on a listener that uses TLS; fail loudly
        // instead of silently running without the authentication the operator asked for.
        if(httpClientAuth&&!httpTlsEnabled)throw new IllegalArgumentException("ssl_client_authentication requires ssl_enabled");
        if(tcpClientAuth&&!tcpTlsEnabled)throw new IllegalArgumentException("s2s_tcp_ssl_client_authentication requires s2s_tcp_ssl_enabled and s2s_tcp_enabled");
        // Certificate material is shared, so it is allowed if EITHER listener uses TLS, and an error only
        // when neither does (it would be silently unused).
        if(!httpTlsEnabled&&!tcpTlsEnabled&&(keystore!=null||certificate!=null||key!=null||clientCa!=null))
            throw new IllegalArgumentException("TLS material requires TLS enabled");
        // Each listener gets its own context; a plaintext listener receives no material at all.
        tls=tlsFor(httpTlsEnabled,httpClientAuth,state,config,keystore,certificate,key,clientCa);
        tcpTls=tlsFor(tcpTlsEnabled,tcpClientAuth,state,config,keystore,certificate,key,clientCa);
        acks=new AckManager(state);
        if(!config.get(FILE).isEmpty())reload.scheduleWithFixedDelay(tokens::reload,1,1,TimeUnit.SECONDS);
    }
    /**
     * Build the TLS context for ONE listener. A plaintext listener gets an empty, disabled config and no
     * key material at all, so it can never accidentally serve a certificate. A TLS listener uses the
     * shared certificate options (keystore, or PEM files, or a generated self-signed identity under the
     * state directory) plus its OWN client-authentication switch. Two listeners that both use TLS share
     * the same identity because the generated one is created once and then reused.
     */
    private static TlsConfig tlsFor(boolean enabled,boolean clientAuth,Path state,Configuration config,Path keystore,Path certificate,Path key,Path clientCa)throws Exception{
        if(!enabled)return new TlsConfig(new TlsConfig.Options(false,null,"",null,"PKCS12","",null,null,null,false));
        return new TlsConfig(new TlsConfig.Options(true,state.resolve("identity"),config.get(SANS),keystore,
            config.get(STORETYPE),config.get(PASSWORD).getValue(),certificate,key,clientCa,clientAuth));
    }
    private static int n(Configuration config,String name){return Math.toIntExact(config.get(NUMBERS.get(name)));}
    private static Path path(String s){return s.isEmpty()?null:Path.of(s);}
    @Override public void start(Consumer<Map<String,Object>> consumer){
        try{
            // One dispatcher serves every supported path. The consumer is shared
            // by concurrent requests, so cross-request insertion order can interleave.
            synchronized(this){
                if(stopped)return;
                // A plaintext listener is allowed but never silent: tell the operator at startup.
                if(!httpTlsEnabled)diagnostic.accept("HEC HTTP listener is plaintext; tokens travel unencrypted. Use only on an isolated network");
                if(tcpEnabled&&!tcpTlsEnabled)diagnostic.accept("S2S TCP listener is plaintext and has no token authentication; restrict network access or set s2s_tcp_ssl_enabled => true");
                server=new HecServer(host,port,tls,limits,tokens,acks,consumer,resources);server.start();
                if(tcpEnabled){tcpServer=new S2STcpServer(host,tcpPort,tcpTls,tcpLimits,resources,consumer,tcpIndex,tcpIndexes,diagnostic);tcpServer.start();}
            }
            synchronized(this){while(!stopped){
                if(server.failure()!=null)throw new IllegalStateException("HEC listener failed",server.failure());
                if(tcpServer!=null&&tcpServer.failure()!=null)throw new IllegalStateException("S2S TCP listener failed",tcpServer.failure());
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
            // Interrupt BOTH listeners before joining either, so a blocked TCP
            // writer cannot consume the HTTP listener's shutdown grace or vice versa.
            if(closing!=null)closing.beginStop();if(tcpServer!=null)tcpServer.beginStop();
            RuntimeException shutdown=null;
            try{if(closing!=null)closing.closeBy(deadline);}catch(RuntimeException error){shutdown=error;}
            try{if(tcpServer!=null)tcpServer.closeBy(deadline);}catch(RuntimeException error){if(shutdown==null)shutdown=error;else shutdown.addSuppressed(error);}
            if(shutdown!=null)throw shutdown;
            interrupted|=Thread.interrupted();
            while(!reload.isTerminated()){
                long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException("policy reload did not terminate");
                try{reload.awaitTermination(left,TimeUnit.NANOSECONDS);}
                catch(InterruptedException stopInterrupt){interrupted=true;}
            }
            try{acks.close();}finally{resources.close();}
        }catch(java.io.IOException e){stopFailure=new IllegalStateException("ACK state close failed",e);throw stopFailure;}
        catch(RuntimeException e){stopFailure=e;throw e;}
        finally{done.countDown();if(interrupted)Thread.currentThread().interrupt();}
    }
    @Override public void awaitStop()throws InterruptedException{done.await();if(stopFailure!=null)throw stopFailure;}
    @Override public String getId(){return id;}
    @Override public Collection<PluginConfigSpec<?>> configSchema(){
        // HTTP format is selected by path, not an input-wide JSON codec. Optional
        // TCP shares TLS/limits but has its own index defaults and wire handshake.
        List<PluginConfigSpec<?>> schema=new ArrayList<>(List.of(HOST,PORT,TOKENS,FILE,STATE,TLS,SANS,STORE,STORETYPE,PASSWORD,CERT,KEY,CA,MTLS,TCP,TCPPORT,TCPINDEX,TCPINDEXES,TCPEVENT,TCPTLS,TCPMTLS,METADATA,S2SMETADATA));
        schema.addAll(NUMBERS.values());
        // Accept Logstash's standard input options (id, enable_metric, add_field, tags, type).
        // codec is removed on purpose: this input emits native maps and has no codec stage, so
        // accepting one would be silently ignored.
        List<PluginConfigSpec<?>> all=new ArrayList<>(PluginHelper.commonInputSettings(schema));
        all.removeIf(spec->spec.name().equals("codec"));
        return all;
    }
}
