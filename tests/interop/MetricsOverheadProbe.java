package org.logstashplugins.hec;

import java.util.*;
import java.util.function.Consumer;

/** Isolate the atomic handoff wrapper from HTTP, queue and output scheduling. */
public final class MetricsOverheadProbe {
    private static volatile long consumed;
    private static final Map<String,Object> EVENT=Map.of("event","synthetic");
    private static final Consumer<Map<String,Object>> SINK=event->consumed++;
    private static long sample(HecMetrics metrics,int calls){
        long start=System.nanoTime();
        for(int i=0;i<calls;i++)metrics.handoff("http_raw",SINK,EVENT);
        return System.nanoTime()-start;
    }
    public static void main(String[] args)throws Exception{
        var enabled=new HecMetrics();
        for(int i=0;i<10;i++){sample(enabled,10000);sample(HecMetrics.NONE,10000);}
        var on=new ArrayList<Long>();var off=new ArrayList<Long>();int calls=100000;
        for(int i=0;i<8;i++){
            if(i%2==0){on.add(sample(enabled,calls));off.add(sample(HecMetrics.NONE,calls));}
            else{off.add(sample(HecMetrics.NONE,calls));on.add(sample(enabled,calls));}
        }
        if(enabled.value("handoff.http_raw.returned")!=900000||consumed!=1800000)throw new AssertionError("probe calls not executed");
        System.out.println(HecProtocol.JSON.writeValueAsString(Map.of("scope","host JVM synthetic Consumer; excludes HTTP/queue/output and contention",
            "calls_per_sample",calls,"enabled_total_nanos",on,"disabled_total_nanos",off,"java_version",System.getProperty("java.version"))));
    }
}
