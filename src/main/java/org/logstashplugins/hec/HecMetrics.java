package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Per-instance, bounded schema. Collectors only read atomics; they never own operational state. */
final class HecMetrics {
    static final List<String> ROUTES=List.of("event","raw","s2s","ack","health","unknown");
    static final List<String> OUTCOMES=List.of("success","unauthorized","forbidden","invalid","busy","internal");
    static final List<String> REASONS=List.of("timeout","metadata-conflict","structured-transition","coordinate-gap-or-reordering","reordering","new-start");
    static final List<String> HANDOFFS=List.of("http_event","http_raw","http_s2s","tcp","assembly_direct","outbox");
    static final Set<String> SCHEMA;
    static {
        var keys=new LinkedHashSet<String>();
        for(String route:ROUTES)for(String outcome:OUTCOMES)keys.add("http."+route+"."+outcome);
        keys.addAll(List.of("http.connection_rejected","http.response_failures","tcp.connection_accepted","tcp.connection_rejected",
            "tcp.connection_closed","tcp.connection_failures","tcp.response_failures","tcp.data.success","tcp.data.failure","tcp.control.success","tcp.control.failure",
            "assembly.enabled","assembly.blocked","assembly.pending","assembly.outbox","assembly.receipts","assembly.live_bytes","assembly.reserved_bytes",
            "assembly.quota_bytes","assembly.utilization_basis_points","assembly.physical_bytes_last_observed","assembly.journal_bytes_last_observed",
            "assembly.contributions","last_durable_acceptance_epoch_millis","last_handoff_epoch_millis","last_commit_epoch_millis","handoff.active"));
        for(String reason:REASONS)keys.add("assembly.flush."+reason.replace('-','_'));
        for(String kind:HANDOFFS){keys.add("handoff."+kind+".returned");timingKeys(keys,"handoff."+kind);}
        for(String kind:List.of("capacity","commit","publication","compaction","fsync"))timingKeys(keys,"store."+kind);
        SCHEMA=Collections.unmodifiableSet(keys);
    }
    private static void timingKeys(Set<String> keys,String prefix){for(String suffix:List.of("attempts","count","failures","total_nanos"))keys.add(prefix+"."+suffix);}
    static final HecMetrics NONE=new HecMetrics(false);
    private final Map<String,Scalar> values;
    private final boolean enabled;
    HecMetrics(){this(true);}
    private HecMetrics(boolean enabled){
        this.enabled=enabled;
        var scalars=new LinkedHashMap<String,Scalar>();
        if(enabled)for(String key:SCHEMA)scalars.put(key,new Scalar(key.endsWith("epoch_millis")?-1:0));
        values=Collections.unmodifiableMap(scalars);
    }
    /** Public for both pinned serializers' reflective metric adapters. */
    public static final class Scalar implements UserMetric<Long> {
        private final AtomicLong value;
        Scalar(long initial){value=new AtomicLong(initial);}
        @Override @com.fasterxml.jackson.annotation.JsonValue
        public Long getValue(){return value.get();}
        // Node Stats' extended pipeline formatter reads both `value` and
        // `type` through JRuby bean access, even for Java UserMetric values.
        public String getType(){return "gauge/number";}
    }
    static HecMetrics create(boolean enabled,Context context,Plugin plugin,Consumer<String> diagnostic){
        if(!enabled)return NONE;
        var metrics=new HecMetrics();
        try{metrics.register(context.getMetric(plugin));}
        catch(RuntimeException|LinkageError unavailable){
            // One value-free diagnostic, including when the diagnostic reporter itself is broken.
            try{diagnostic.accept("HEC metrics collector unavailable; ingestion continues with local metrics");}catch(RuntimeException|LinkageError ignored){}
        }
        return metrics;
    }
    void register(NamespacedMetric collector){
        if(!enabled)return;
        if(collector==null)throw new IllegalStateException("missing metrics collector");
        var root=collector.namespace("hec");
        for(var entry:values.entrySet()){
            String[] path=entry.getKey().split("\\.");
            var namespace=path.length==1?root:root.namespace(Arrays.copyOf(path,path.length-1));
            Scalar scalar=entry.getValue();
            namespace.register(path[path.length-1],new UserMetric.Factory<Scalar>(){
                public Class<Scalar> getType(){return Scalar.class;}
                public Scalar create(String name){return scalar;}
                public Scalar nullImplementation(){return new Scalar(0);}
            });
        }
    }
    boolean enabled(){return enabled;}
    long value(String key){return enabled?values.get(key).value.get():0;}
    void set(String key,long value){if(enabled)values.get(key).value.set(value);}
    void add(String key,long amount){if(enabled)values.get(key).value.getAndUpdate(before->saturated(before,amount));}
    void increment(String key){add(key,1);}
    static long saturated(long before,long amount){return amount>Long.MAX_VALUE-before?Long.MAX_VALUE:before+amount;}
    void timestamp(String key){if(enabled)values.get(key).value.accumulateAndGet(System.currentTimeMillis(),Math::max);}
    long begin(String prefix){if(!enabled)return 0;increment(prefix+".attempts");return System.nanoTime();}
    void timed(String prefix,long start,boolean success){
        if(!enabled)return;
        increment(prefix+".count");add(prefix+".total_nanos",Math.max(0,System.nanoTime()-start));
        if(!success)increment(prefix+".failures");
    }
    void http(String route,String outcome){increment("http."+route+"."+outcome);}
    static String outcome(int status){return switch(status){case 401->"unauthorized";case 403->"forbidden";case 503->"busy";default->status<500?"invalid":"internal";};}
    void handoff(String kind,Consumer<Map<String,Object>> sink,Map<String,Object> event){
        if(!enabled){sink.accept(event);return;}
        long start=begin("handoff."+kind);boolean success=false;increment("handoff.active");
        try{sink.accept(event);success=true;increment("handoff."+kind+".returned");timestamp("last_handoff_epoch_millis");}
        finally{values.get("handoff.active").value.decrementAndGet();timed("handoff."+kind,start,success);}
    }
}
