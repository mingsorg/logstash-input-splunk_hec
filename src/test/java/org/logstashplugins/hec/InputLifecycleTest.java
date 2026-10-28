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
    SplunkHec input()throws Exception{return input(Map.of());}
    SplunkHec input(Map<String,Object> extra)throws Exception{
        int port;try(var listener=new ServerSocket(0)){port=listener.getLocalPort();}
        Map<String,Object> values=new HashMap<>(Map.of("host","127.0.0.1","port",(long)port,"ssl_enabled",false,
            "state_directory",directory.toString(),"shutdown_grace_ms",2000L,
            "tokens_json",new Password(ProtocolTest.INLINE)));
        values.putAll(extra);
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

    /** Real latest heavy forwarders sent a ~1.2 MB internal record; rejecting it would wedge their queue. */
    @Test void largeHeavyForwarderRecordIsAcceptedByDefaultAndRefusedWithAnExplicitSmallerTcpCap()throws Exception{
        for(boolean limited:List.of(false,true)){
            int tcpPort;try(var listener=new ServerSocket(0)){tcpPort=listener.getLocalPort();}
            Map<String,Object> extra=new HashMap<>(Map.of("s2s_tcp_enabled",true,"s2s_tcp_port",(long)tcpPort));
            if(limited)extra.put("s2s_tcp_max_event_bytes",65536L);
            SplunkHec input=input(extra);List<Map<String,Object>> events=Collections.synchronizedList(new ArrayList<>());
            Thread running=Thread.ofVirtual().start(()->{try{input.start(events::add);}catch(Throwable ignored){}});
            try(Socket socket=connectTcp(tcpPort)){
                byte[] header=new byte[400];
                System.arraycopy(S2STcpProtocol.SIGNATURE.getBytes(),0,header,0,S2STcpProtocol.SIGNATURE.length());
                System.arraycopy("hf-test".getBytes(),0,header,128,7);System.arraycopy("8089".getBytes(),0,header,384,4);
                socket.getOutputStream().write(header);
                S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("__s2s_capabilities","ack=1;compression=0"));
                try(var memory=new MemoryBudget(Limits.defaults().aggregate()).lease()){S2STcpProtocol.frame(socket.getInputStream(),Limits.defaults(),memory);}
                S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000002","__s2s_capabilities","v4=1;pl=7"));
                socket.getOutputStream().write(new S2STest.Body().meta().op(0xfc).v(1).v(0x3f).v(7).v(100).v(0).v(2).v(1790000000).v(0).str("x".repeat(1_241_039)).out.toByteArray());
                socket.getOutputStream().flush();
                if(limited){assertEquals(-1,socket.getInputStream().read());assertTrue(events.isEmpty());}
                else{assertEquals(0xfb,socket.getInputStream().read());assertEquals(2,socket.getInputStream().read());assertEquals(1,events.size());}
            }finally{input.stop();running.join(5000);}
        }
    }
    private static Socket connectTcp(int port)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(true)try{Socket socket=new Socket("127.0.0.1",port);socket.setSoTimeout(10000);return socket;}
        catch(ConnectException retry){if(System.nanoTime()>until)throw retry;Thread.sleep(25);}
    }
}
