package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.lang.reflect.Proxy;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.nio.charset.StandardCharsets;
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

    @Test void schemaAcceptsStandardLogstashInputOptionsButNotACodec()throws Exception{
        Set<String> names=new HashSet<>();for(var spec:input().configSchema())names.add(spec.name());
        for(String standard:List.of("id","enable_metric","add_field","tags","type"))assertTrue(names.contains(standard),standard);
        assertFalse(names.contains("codec"));
        for(String own:List.of("port","s2s_tcp_enabled","s2s_tcp_max_event_bytes","max_event_bytes","ssl_enabled"))assertTrue(names.contains(own),own);
    }

    // ---- per-listener TLS: HEC defaults to TLS, classic TCP defaults to plaintext -------------------
    private static int freePort()throws Exception{try(var listener=new ServerSocket(0)){return listener.getLocalPort();}}
    private static SSLContext trust(Path certificate)throws Exception{
        KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,new char[0]);
        try(var in=java.nio.file.Files.newInputStream(certificate)){store.setCertificateEntry("server",CertificateFactory.getInstance("X.509").generateCertificate(in));}
        var managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());managers.init(store);
        SSLContext context=SSLContext.getInstance("TLS");context.init(null,managers.getTrustManagers(),new SecureRandom());return context;
    }
    private static Socket waitSocket(int port,SSLContext context)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
        while(true)try{
            Socket socket=context==null?new Socket("127.0.0.1",port):context.getSocketFactory().createSocket("127.0.0.1",port);
            socket.setSoTimeout(5000);
            if(socket instanceof SSLSocket ssl){var parameters=ssl.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");ssl.setSSLParameters(parameters);ssl.startHandshake();}
            return socket;
        }catch(ConnectException retry){if(System.nanoTime()>until)throw retry;Thread.sleep(25);}
    }
    /** Complete the classic handshake as far as the server's capability reply. */
    private static void tcpHello(Socket socket)throws Exception{
        byte[] header=new byte[400];
        System.arraycopy(S2STcpProtocol.SIGNATURE.getBytes(StandardCharsets.US_ASCII),0,header,0,S2STcpProtocol.SIGNATURE.length());
        System.arraycopy("tls-test".getBytes(),0,header,128,8);System.arraycopy("8089".getBytes(),0,header,384,4);
        socket.getOutputStream().write(header);
        S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("__s2s_capabilities","ack=1;compression=0"));
        try(var memory=new MemoryBudget(Limits.defaults().aggregate()).lease()){
            assertTrue(S2STcpProtocol.frame(socket.getInputStream(),Limits.defaults(),memory).pairs().get("__s2s_control_msg").contains("v4=true"));
        }
    }
    private static int status(String url,SSLContext context)throws Exception{
        var builder=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5));if(context!=null)builder.sslContext(context);
        return builder.build().send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build(),HttpResponse.BodyHandlers.discarding()).statusCode();
    }
    private SplunkHec startedInput(Map<String,Object> extra,Thread[] running)throws Exception{
        SplunkHec input=input(extra);
        running[0]=Thread.ofVirtual().start(()->{try{input.start(e->{});}catch(Throwable ignored){}});
        return input;
    }
    @Test void defaultsGiveTlsOnTheHttpListenerAndPlaintextOnTheTcpListener()throws Exception{
        int http=freePort(),tcp=freePort();Path state=directory.resolve("defaults");
        Thread[] running=new Thread[1];
        SplunkHec input=startedInput(Map.of("port",(long)http,"ssl_enabled",true,"s2s_tcp_enabled",true,"s2s_tcp_port",(long)tcp,"state_directory",state.toString()),running);
        try{
            // HTTPS with a verified generated certificate works; plaintext HTTP to the same port does not.
            try(Socket probe=waitSocket(http,trust(state.resolve("identity/server.crt")))){assertTrue(probe instanceof SSLSocket);}
            assertEquals(200,status("https://127.0.0.1:"+http+"/services/collector/health",trust(state.resolve("identity/server.crt"))));
            assertThrows(Exception.class,()->status("http://127.0.0.1:"+http+"/services/collector/health",null));
            // The classic TCP port speaks plaintext by default.
            try(Socket socket=waitSocket(tcp,null)){assertFalse(socket instanceof SSLSocket);tcpHello(socket);}
            // And it is not a TLS endpoint: a TLS client cannot complete a handshake there.
            assertThrows(Exception.class,()->{try(Socket socket=waitSocket(tcp,trust(state.resolve("identity/server.crt")))){tcpHello(socket);}});
        }finally{input.stop();running[0].join(5000);}
    }
    @Test void httpCanBePlaintextWhileTcpUsesTls()throws Exception{
        int http=freePort(),tcp=freePort();Path state=directory.resolve("inverse");
        Thread[] running=new Thread[1];
        SplunkHec input=startedInput(Map.of("port",(long)http,"ssl_enabled",false,"s2s_tcp_enabled",true,"s2s_tcp_ssl_enabled",true,"s2s_tcp_port",(long)tcp,"state_directory",state.toString()),running);
        try{
            try(Socket socket=waitSocket(http,null)){assertFalse(socket instanceof SSLSocket);}
            assertEquals(200,status("http://127.0.0.1:"+http+"/services/collector/health",null));
            try(Socket socket=waitSocket(tcp,trust(state.resolve("identity/server.crt")))){assertTrue(socket instanceof SSLSocket);tcpHello(socket);}
        }finally{input.stop();running[0].join(5000);}
    }
    @Test void bothListenersCanBeTlsOrBothPlaintext()throws Exception{
        for(boolean encrypted:List.of(true,false)){
            int http=freePort(),tcp=freePort();Path state=directory.resolve("both-"+encrypted);
            Thread[] running=new Thread[1];
            SplunkHec input=startedInput(Map.of("port",(long)http,"ssl_enabled",encrypted,"s2s_tcp_enabled",true,"s2s_tcp_ssl_enabled",encrypted,"s2s_tcp_port",(long)tcp,"state_directory",state.toString()),running);
            try{
                SSLContext context=encrypted?trust(state.resolve("identity/server.crt")):null;
                try(Socket socket=waitSocket(tcp,context)){assertEquals(encrypted,socket instanceof SSLSocket);tcpHello(socket);}
                assertEquals(200,status((encrypted?"https":"http")+"://127.0.0.1:"+http+"/services/collector/health",context));
            }finally{input.stop();running[0].join(5000);}
        }
    }
    @Test void inconsistentPerListenerTlsSettingsFailAtStartup()throws Exception{
        var message=assertThrows(IllegalArgumentException.class,()->input(Map.of("state_directory",directory.resolve("e1").toString(),"ssl_enabled",false,"ssl_client_authentication",true))).getMessage();
        assertEquals("ssl_client_authentication requires ssl_enabled",message);
        message=assertThrows(IllegalArgumentException.class,()->input(Map.of("state_directory",directory.resolve("e2").toString(),"s2s_tcp_enabled",true,"s2s_tcp_ssl_client_authentication",true))).getMessage();
        assertTrue(message.startsWith("s2s_tcp_ssl_client_authentication requires"),message);
        message=assertThrows(IllegalArgumentException.class,()->input(Map.of("state_directory",directory.resolve("e3").toString(),"ssl_enabled",false,"ssl_keystore",directory.resolve("x.p12").toString()))).getMessage();
        assertEquals("TLS material requires TLS enabled",message);
        // Material is allowed when only the TCP listener uses TLS; a missing file then fails on its own.
        assertThrows(Exception.class,()->input(Map.of("state_directory",directory.resolve("e4").toString(),"ssl_enabled",false,"s2s_tcp_enabled",true,"s2s_tcp_ssl_enabled",true,"ssl_keystore",directory.resolve("missing.p12").toString())));
    }
    @Test void hecMetadataAcceptsOnlyDocumentedModes()throws Exception{
        for(String ok:List.of("full","id_only","none","FULL")){SplunkHec i=input(Map.of("state_directory",directory.resolve("m-"+ok).toString(),"hec_metadata",ok));assertNotNull(i);i.stop();}
        assertEquals("hec_metadata must be full, id_only or none",assertThrows(IllegalArgumentException.class,()->input(Map.of("state_directory",directory.resolve("m-bad").toString(),"hec_metadata","some"))).getMessage());
    }
}
