package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.lang.reflect.Proxy;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class InputLifecycleTest {
    @TempDir Path directory;
    SplunkHec input()throws Exception{
        int port;try(var listener=new ServerSocket(0)){port=listener.getLocalPort();}
        Map<String,Object> values=Map.of("host","127.0.0.1","port",(long)port,"ssl_enabled",false,
            "state_directory",directory.toString(),"shutdown_grace_ms",2000L,
            "tokens_json",new Password(ProtocolTest.INLINE));
        Configuration configuration=new Configuration(){
            @SuppressWarnings("unchecked") public <T>T get(PluginConfigSpec<T> spec){
                if(values.containsKey(spec.name()))return (T)values.get(spec.name());
                return spec.type()==Password.class?(T)new Password(spec.getRawDefaultValue()):spec.defaultValue();
            }
            public Object getRawValue(PluginConfigSpec<?> spec){return values.get(spec.name());}
            public boolean contains(PluginConfigSpec<?> spec){return values.containsKey(spec.name());}
            public Collection<String> allKeys(){return values.keySet();}
        };
        Context context=(Context)Proxy.newProxyInstance(Context.class.getClassLoader(),new Class<?>[]{Context.class},
            (proxy,method,args)->method.getName().equals("getLogger")?LogManager.getLogger(InputLifecycleTest.class):null);
        return new SplunkHec("lifecycle-test",configuration,context);
    }
    HecServer server(SplunkHec input)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);HecServer server=null;
        while(server==null&&System.nanoTime()<until){server=(HecServer)HttpTlsTest.privateField(input,"server");Thread.sleep(5);}
        assertNotNull(server);return server;
    }
    @Test void interruptedStopJoinsWorkersAndReleasesTheAckStateLock()throws Exception{
        SplunkHec input=input();CountDownLatch entered=new CountDownLatch(1);
        var failure=new AtomicReference<Throwable>();
        Thread running=Thread.ofVirtual().start(()->{try{input.start(e->{entered.countDown();try{Thread.sleep(60000);}catch(InterruptedException stop){throw HecException.busy();}});}catch(Throwable e){failure.set(e);}});
        try{
            HecServer server=server(input);
            var pending=HttpClient.newHttpClient().sendAsync(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+server.port()+"/services/collector/event"))
                .timeout(Duration.ofSeconds(10)).header("Authorization","Splunk "+ProtocolTest.SECRET)
                .POST(HttpRequest.BodyPublishers.ofString("{\"event\":\"blocked\"}")).build(),HttpResponse.BodyHandlers.ofString());
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            var stopped=new AtomicReference<Throwable>();
            Thread stopping=Thread.ofVirtual().start(()->{Thread.currentThread().interrupt();try{input.stop();assertTrue(Thread.currentThread().isInterrupted());}catch(Throwable e){stopped.set(e);}});
            stopping.join(5000);running.join(5000);assertFalse(stopping.isAlive());assertFalse(running.isAlive());assertNull(stopped.get());
            input.awaitStop();assertNull(failure.get());
            try(var reclaimed=new AckManager(directory)) { assertNotNull(reclaimed); }
            pending.cancel(true);
        }finally{input.stop();running.join(5000);}
    }
    @Test void unexpectedListenerFailureTerminatesTheInputAndReleasesState()throws Exception{
        SplunkHec input=input();var failure=new AtomicReference<Throwable>();
        Thread running=Thread.ofVirtual().start(()->{try{input.start(e->{});}catch(Throwable e){failure.set(e);}});
        try{
            HecServer server=server(input);
            ((ServerSocket)HttpTlsTest.privateField(server,"listener")).close();
            running.join(5000);assertFalse(running.isAlive());assertNotNull(failure.get());assertNotNull(server.failure());
            input.awaitStop();try(var reclaimed=new AckManager(directory)){assertNotNull(reclaimed);}
        }finally{input.stop();running.join(5000);}
    }
}
