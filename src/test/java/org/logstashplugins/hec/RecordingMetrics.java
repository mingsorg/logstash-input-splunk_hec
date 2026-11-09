package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Records the actual factory getters, rather than approximating gauge registration. */
final class RecordingMetrics {
    final Map<String,UserMetric<?>> registered=new ConcurrentHashMap<>();
    NamespacedMetric namespace(String prefix){
        return (NamespacedMetric)Proxy.newProxyInstance(NamespacedMetric.class.getClassLoader(),new Class<?>[]{NamespacedMetric.class},(proxy,method,args)->{
            return switch(method.getName()){
                case "namespace" -> namespace(prefix+String.join(".",(String[])args[0])+".");
                case "register" -> {
                    var factory=(UserMetric.Factory<?>)args[1];var metric=factory.create((String)args[0]);
                    if(registered.putIfAbsent(prefix+args[0],metric)!=null)throw new AssertionError("duplicate registration");
                    yield metric;
                }
                default -> throw new AssertionError("unexpected metric call: "+method.getName());
            };
        });
    }
    Map<String,Long> snapshot(){
        var result=new TreeMap<String,Long>();registered.forEach((key,metric)->result.put(key,((Number)metric.getValue()).longValue()));return result;
    }
}
