package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import javax.net.ssl.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

class HttpTlsTest {
    @TempDir Path dir;
    static final String CHANNEL="12345678-1234-4234-8234-123456789abc";
    final List<Map<String,Object>> received=new CopyOnWriteArrayList<>();
    TokenStore store()throws Exception{
        return new TokenStore(Path.of("tests/interop/oracle/inputs.conf"),"[]",s->{});
    }
    TlsConfig plain()throws Exception{return new TlsConfig(new TlsConfig.Options(false,null,"",null,"PKCS12","",null,null,null,false));}
    TlsConfig self(String sans)throws Exception{return new TlsConfig(new TlsConfig.Options(true,dir.resolve("identity"),sans,null,"PKCS12","",null,null,null,false));}
    HttpClient client(){return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();}
    HttpResponse<String> post(HttpClient client,String base,String path,String body,String secret)throws Exception{
        return client.send(HttpRequest.newBuilder(URI.create(base+path)).timeout(Duration.ofSeconds(10))
            .header("Authorization","Splunk "+secret).header("X-Splunk-Request-Channel",CHANNEL)
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    @Test void realOracleWireCorpus()throws Exception{
        var fixture=HecProtocol.JSON.readTree(Files.readAllBytes(Path.of("tests/interop/evidence/oracle-http.json")));
        int checked=0;
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            for(var observation:fixture.get("observations")){
                String name=observation.get("name").asText();
                if(name.startsWith("ack-poll:")&&observation.get("response").get("status").asInt()!=400)continue; // allocator-specific success state tested separately
                var headers=observation.get("request_headers");
                byte[] body=Base64.getDecoder().decode(observation.get("request_body_base64").asText());
                HttpRequest.Builder request=HttpRequest.newBuilder(URI.create(base+observation.get("path").asText())).timeout(Duration.ofSeconds(10));
                headers.fields().forEachRemaining(e->request.header(e.getKey(),e.getValue().asText()));
                request.method(observation.get("method").asText(),HttpRequest.BodyPublishers.ofByteArray(body));
                int before=received.size();var response=client.send(request.build(),HttpResponse.BodyHandlers.ofString());
                var expected=HecProtocol.JSON.readTree(observation.get("response").get("body").asText());
                {
                    assertEquals(observation.get("response").get("status").asInt(),response.statusCode(),name+" "+response.body());
                    var actual=HecProtocol.JSON.readTree(response.body());
                    if(expected.has("ackId")){
                        assertTrue(actual.path("ackId").isIntegralNumber());
                        ((com.fasterxml.jackson.databind.node.ObjectNode)expected).remove("ackId");
                        ((com.fasterxml.jackson.databind.node.ObjectNode)actual).remove("ackId");
                    }
                    assertEquals(expected,actual,name);
                    if(observation.has("accepted_event_count")&&!name.startsWith("raw:")&&!name.contains("/raw")&&!name.equals("time_string")&&!name.equals("time_nanos"))
                        assertEquals(observation.get("accepted_event_count").asInt(),received.size()-before,name);
                }
                checked++;
            }
        }
        assertTrue(checked>100,"oracle corpus unexpectedly not exercised");
        System.out.println("Compared "+checked+" real-oracle wire cases");
    }
    @Test void ackCompletionConsumesOnceAndMalformedS2SQueuesNothing()throws Exception{
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();String secret="22222222-2222-4222-8222-222222222222";
            var response=post(client,base,"/services/collector/event","{\"event\":\"x\"}",secret);
            assertEquals(200,response.statusCode(),response.body());long id=HecProtocol.JSON.readTree(response.body()).get("ackId").longValue();
            for(boolean expected:List.of(true,false)){
                var poll=post(client,base,"/services/collector/ack","{\"acks\":["+id+","+id+"]}",secret);
                assertEquals(expected,HecProtocol.JSON.readTree(poll.body()).path("acks").path(Long.toString(id)).asBoolean());
            }
            int count=received.size();byte[] malformed=new S2STest.Body().meta().event(0x4a,0).str("valid prefix").op(0xfb).compressed();
            var bad=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/s2s"))
                .header("Authorization","Splunk "+secret).header("X-Splunk-Request-Channel",CHANNEL)
                .POST(HttpRequest.BodyPublishers.ofByteArray(malformed)).build(),HttpResponse.BodyHandlers.ofString());
            assertEquals(400,bad.statusCode(),bad.body());assertEquals(6,HecProtocol.JSON.readTree(bad.body()).path("code").asInt());
            assertFalse(bad.body().contains("ackId"));assertEquals(count,received.size());
        }
    }
    @Test void overloadHasIndependentHealthAndStopJoinsWorkers()throws Exception{
        Limits l=new Limits(1,4,1024,8192,1<<20,512,10,10,2000,30,1000);
        CountDownLatch entered=new CountDownLatch(1);CountDownLatch terminated=new CountDownLatch(1);
        Consumer<Map<String,Object>> blocked=e->{entered.countDown();try{Thread.sleep(60000);}catch(InterruptedException x){Thread.currentThread().interrupt();throw HecException.busy();}finally{terminated.countDown();}};
        try(var acks=new AckManager(dir)){
            HecServer server=new HecServer("127.0.0.1",0,plain(),l,store(),acks,blocked);server.start();
            String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            var pending=client.sendAsync(HttpRequest.newBuilder(URI.create(base+"/services/collector/event"))
                .header("Authorization","Splunk "+ProtocolTest.SECRET).POST(HttpRequest.BodyPublishers.ofString("{\"event\":\"x\"}")).build(),HttpResponse.BodyHandlers.ofString());
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            assertEquals(503,post(client,base,"/services/collector/event","{\"event\":\"x\"}",ProtocolTest.SECRET).statusCode());
            var health=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/health")).GET().build(),HttpResponse.BodyHandlers.ofString());
            assertEquals(503,health.statusCode());assertEquals(18,HecProtocol.JSON.readTree(health.body()).path("code").asInt());
            try(Socket idle=new Socket("127.0.0.1",server.port())){
                long started=System.nanoTime();server.close();assertTrue(System.nanoTime()-started<TimeUnit.SECONDS.toNanos(2));
            }
            assertTrue(terminated.await(1,TimeUnit.SECONDS));pending.cancel(true);
        }
    }
    @Test void requestPolicySnapshotRevocationAckDisableAndRotation()throws Exception{
        Path file=dir.resolve("inputs.conf");String stanza="[http://name]\ntoken = "+ProtocolTest.SECRET+"\nuseACK = true\nindexes = main\n";
        Files.writeString(file,stanza);TokenStore tokens=new TokenStore(file,"[]",s->{});
        CountDownLatch first=new CountDownLatch(1),release=new CountDownLatch(1);
        Consumer<Map<String,Object>> sink=e->{if(first.getCount()>0){first.countDown();try{assertTrue(release.await(5,TimeUnit.SECONDS));}catch(InterruptedException x){throw new IllegalStateException(x);}}received.add(e);};
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),tokens,acks,sink)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            var pending=client.sendAsync(HttpRequest.newBuilder(URI.create(base+"/services/collector/event"))
                .header("Authorization","Splunk "+ProtocolTest.SECRET).header("X-Splunk-Request-Channel",CHANNEL)
                .POST(HttpRequest.BodyPublishers.ofString("{\"event\":\"one\"}{\"event\":\"two\"}")).build(),HttpResponse.BodyHandlers.ofString());
            assertTrue(first.await(5,TimeUnit.SECONDS));Files.writeString(file,"[http]\n");assertTrue(tokens.reload());release.countDown();
            var completed=pending.get(5,TimeUnit.SECONDS);assertEquals(200,completed.statusCode());assertEquals(2,received.size());
            long id=HecProtocol.JSON.readTree(completed.body()).path("ackId").longValue();
            assertEquals(403,post(client,base,"/services/collector/ack","{\"acks\":["+id+"]}",ProtocolTest.SECRET).statusCode());
            Files.writeString(file,stanza.replace("name","renamed").replace("useACK = true","useACK = false"));assertTrue(tokens.reload());
            assertEquals(14,HecProtocol.JSON.readTree(post(client,base,"/services/collector/ack","{\"acks\":["+id+"]}",ProtocolTest.SECRET).body()).path("code").asInt());
            Files.writeString(file,stanza.replace("name","renamed"));assertTrue(tokens.reload());
            assertTrue(HecProtocol.JSON.readTree(post(client,base,"/services/collector/ack","{\"acks\":["+id+"]}",ProtocolTest.SECRET).body()).path("acks").path(Long.toString(id)).asBoolean());
            Files.writeString(file,stanza.replace(ProtocolTest.SECRET,"new-secret"));assertTrue(tokens.reload());
            assertEquals(403,post(client,base,"/services/collector/event","{\"event\":\"revoked\"}",ProtocolTest.SECRET).statusCode());
            assertFalse(HecProtocol.JSON.readTree(post(client,base,"/services/collector/ack","{\"acks\":["+id+"]}","new-secret").body()).path("acks").path(Long.toString(id)).asBoolean());
        }finally{release.countDown();}
    }
    @Test void chunkedGzipAndRawRequestBoundaries()throws Exception{
        ByteArrayOutputStream zipped=new ByteArrayOutputStream();try(var gzip=new java.util.zip.GZIPOutputStream(zipped)){gzip.write("one\r\n\ntwo\n \ntail".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            var response=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/raw"))
                .header("Authorization","Splunk "+ProtocolTest.SECRET).header("Content-Encoding","gzip")
                .POST(HttpRequest.BodyPublishers.ofInputStream(()->new ByteArrayInputStream(zipped.toByteArray()))).build(),HttpResponse.BodyHandlers.ofString());
            assertEquals(200,response.statusCode(),response.body());
            assertEquals(List.of("one","two"," ","tail"),received.stream().map(e->e.get("event")).toList());
            assertEquals(200,post(client,base,"/services/collector/raw","next",ProtocolTest.SECRET).statusCode());assertEquals("next",received.getLast().get("event"));
        }
    }
    static Object privateField(Object target,String name)throws Exception{
        var field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);
    }
    @Test void expectContinueIsSentBeforeTheClientSuppliesItsBody()throws Exception{
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();
            try(Socket client=new Socket("127.0.0.1",server.port())){
                client.setSoTimeout(3000);String body="{\"event\":\"after continue\"}";
                var output=client.getOutputStream();
                output.write(("POST /services/collector/event HTTP/1.1\r\nHost: localhost\r\nAuthorization: Splunk "+ProtocolTest.SECRET+"\r\nExpect: 100-continue\r\nContent-Length: "+body.length()+"\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));output.flush();
                var input=new BufferedReader(new InputStreamReader(client.getInputStream(),java.nio.charset.StandardCharsets.UTF_8));
                assertEquals("HTTP/1.1 100 Continue",input.readLine());assertEquals("",input.readLine());
                output.write(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));output.flush();
                assertEquals("HTTP/1.1 200 OK",input.readLine());
            }
            assertEquals("after continue",received.getFirst().get("event"));
        }
    }
    @Test void healthHasReservedCapacityWhenTheIngestionMemoryBudgetIsFull()throws Exception{
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            MemoryBudget budget=(MemoryBudget)privateField(server,"memory");
            try(var occupied=budget.lease()){
                occupied.charge(Limits.defaults().aggregate()-budget.used());
                var health=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/health")).GET().build(),HttpResponse.BodyHandlers.ofString());
                assertEquals(503,health.statusCode());assertEquals(18,HecProtocol.JSON.readTree(health.body()).path("code").asInt());
                assertEquals(503,post(client,base,"/services/collector/event","{\"event\":\"busy\"}",ProtocolTest.SECRET).statusCode());
            }
            assertEquals(200,client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/health")).GET().build(),HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }
    @Test void revocationWhileWaitingForAdmissionRejectsTheWaitingRequest()throws Exception{
        Path file=dir.resolve("policy.conf");Files.writeString(file,"[http://one]\ntoken = "+ProtocolTest.SECRET+"\n");
        TokenStore tokens=new TokenStore(file,"[]",s->{});
        Limits l=new Limits(1,8,8192,16384,2<<20,4096,100,10,10000,5000,1000);
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        Consumer<Map<String,Object>> sink=e->{entered.countDown();try{release.await();}catch(InterruptedException x){throw HecException.busy();}received.add(e);};
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),l,tokens,acks,sink)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();
            var first=CompletableFuture.supplyAsync(()->{try{return post(client,base,"/services/collector/event","{\"event\":\"first\"}",ProtocolTest.SECRET);}catch(Exception e){throw new CompletionException(e);}});
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            var waiting=CompletableFuture.supplyAsync(()->{try{return post(client,base,"/services/collector/event","{\"event\":\"waiting\"}",ProtocolTest.SECRET);}catch(Exception e){throw new CompletionException(e);}});
            Semaphore admission=(Semaphore)privateField(server,"processing");long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
            while(!admission.hasQueuedThreads()&&System.nanoTime()<until)Thread.sleep(5);
            assertTrue(admission.hasQueuedThreads(),"second request must pass initial auth and wait for admission");
            Files.writeString(file,"[http]\n");assertTrue(tokens.reload());release.countDown();
            assertEquals(200,first.get(5,TimeUnit.SECONDS).statusCode());assertEquals(403,waiting.get(5,TimeUnit.SECONDS).statusCode());
            assertEquals(List.of("first"),received.stream().map(e->e.get("event")).toList());
        }finally{release.countDown();}
    }
    @Test void failedQueueInsertionAfterAPrefixNeverReturnsOrCompletesASuccessAck()throws Exception{
        var attempts=new java.util.concurrent.atomic.AtomicInteger();
        Consumer<Map<String,Object>> sink=e->{if(attempts.incrementAndGet()==2)throw new IllegalStateException("queue write failed");received.add(e);};
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,sink)){
            server.start();String base="http://127.0.0.1:"+server.port();HttpClient client=client();String secret="22222222-2222-4222-8222-222222222222";
            var failed=post(client,base,"/services/collector/event","{\"event\":\"prefix\"}{\"event\":\"failed\"}",secret);
            assertEquals(503,failed.statusCode());assertEquals(9,HecProtocol.JSON.readTree(failed.body()).path("code").asInt());assertFalse(failed.body().contains("ackId"));
            assertEquals(List.of("prefix"),received.stream().map(e->e.get("event")).toList());
            assertFalse(HecProtocol.JSON.readTree(post(client,base,"/services/collector/ack","{\"acks\":[0]}",secret).body()).path("acks").path("0").asBoolean());
            var recovered=post(client,base,"/services/collector/event","{\"event\":\"after\"}",secret);assertEquals(200,recovered.statusCode());
            long id=HecProtocol.JSON.readTree(recovered.body()).path("ackId").asLong();
            assertTrue(HecProtocol.JSON.readTree(post(client,base,"/services/collector/ack","{\"acks\":["+id+"]}",secret).body()).path("acks").path(Long.toString(id)).asBoolean());
        }
    }
    @Test void protectedEnvelopeOverridesDoNotInsertOrReturnAnAck()throws Exception{
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),Limits.defaults(),store(),acks,received::add)){
            server.start();String base="http://127.0.0.1:"+server.port();
            for(String name:List.of("@timestamp","@metadata","@version")){
                var response=post(client(),base,"/services/collector/event","{\"event\":\"x\",\""+name+"\":\"override\"}","22222222-2222-4222-8222-222222222222");
                assertEquals(400,response.statusCode());assertFalse(response.body().contains("ackId"));assertTrue(received.isEmpty());
            }
        }
    }
    @Test void responseWritesHaveADeadlineAndCanceledTimersAreRemoved()throws Exception{
        Limits l=new Limits(1,8,8192,16384,2<<20,4096,100,10,500,100,1000);
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,plain(),l,store(),acks,received::add);
            var pair=new ServerSocket(0,1,InetAddress.getLoopbackAddress());var client=new Socket()){
            client.setReceiveBufferSize(1024);client.connect(pair.getLocalSocketAddress());
            try(var sending=pair.accept()){
                sending.setSendBufferSize(1024);
                var method=HecServer.class.getDeclaredMethod("respond",Socket.class,int.class,Map.class);method.setAccessible(true);
                var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
                Thread writer=Thread.ofVirtual().start(()->{try{method.invoke(server,sending,200,Map.of("payload","x".repeat(16<<20)));}catch(Throwable e){failure.set(e);}});
                writer.join(5000);assertFalse(writer.isAlive(),"a non-reading client must not retain a writer indefinitely");assertNotNull(failure.get());
                assertInstanceOf(IOException.class,failure.get().getCause());
            }
            server.start();String base="http://127.0.0.1:"+server.port();
            for(int i=0;i<10;i++)assertEquals(200,post(client(),base,"/services/collector/event","{\"event\":\"x\"}",ProtocolTest.SECRET).statusCode());
            var timers=(ScheduledThreadPoolExecutor)privateField(server,"deadlines");
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(!timers.getQueue().isEmpty()&&System.nanoTime()<until)Thread.sleep(5);
            assertTrue(timers.getQueue().isEmpty(),"completed requests must not accumulate canceled timer tasks");
        }
    }
    static SSLContext trust(Path cert,KeyStore clientIdentity,char[] password)throws Exception{
        KeyStore ca=KeyStore.getInstance("PKCS12");ca.load(null,new char[0]);
        try(InputStream input=Files.newInputStream(cert)){ca.setCertificateEntry("ca",CertificateFactory.getInstance("X.509").generateCertificate(input));}
        TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(ca);
        KeyManager[] keys=null;if(clientIdentity!=null){KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(clientIdentity,password);keys=km.getKeyManagers();}
        SSLContext context=SSLContext.getInstance("TLS");context.init(keys,tm.getTrustManagers(),null);return context;
    }
    @Test void defaultHTTPSPersistedIdentityAndVerifiedHostname()throws Exception{
        TlsConfig tls=self("dns:localhost,ip:127.0.0.1,ip:::1");byte[] identity=Files.readAllBytes(dir.resolve("identity/server.p12"));
        self("dns:ignored-on-reuse");assertArrayEquals(identity,Files.readAllBytes(dir.resolve("identity/server.p12")));
        HttpClient verified=HttpClient.newBuilder().sslContext(trust(dir.resolve("identity/server.crt"),null,null)).build();
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,tls,Limits.defaults(),store(),acks,received::add)){
            server.start();assertEquals(200,post(verified,"https://localhost:"+server.port(),"/services/collector/event","{\"event\":\"secure\"}",ProtocolTest.SECRET).statusCode());
            assertEquals(200,post(verified,"https://127.0.0.1:"+server.port(),"/services/collector/event","{\"event\":\"IP SAN\"}",ProtocolTest.SECRET).statusCode());
            assertThrows(IOException.class,()->post(client(),"https://localhost:"+server.port(),"/services/collector/event","{}",ProtocolTest.SECRET));
        }
        Path other=dir.resolve("wrong-host");TlsConfig wrong=new TlsConfig(new TlsConfig.Options(true,other,"dns:only.example.invalid",null,"PKCS12","",null,null,null,false));
        HttpClient mismatch=HttpClient.newBuilder().sslContext(trust(other.resolve("server.crt"),null,null)).build();
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,wrong,Limits.defaults(),store(),acks,received::add)){
            server.start();assertThrows(IOException.class,()->post(mismatch,"https://localhost:"+server.port(),"/services/collector/event","{}",ProtocolTest.SECRET));
        }
        Files.delete(dir.resolve("identity/password"));assertThrows(IOException.class,()->self("dns:localhost"));
    }
    @Test void providedPKCS12JKSAndPEMAndRequiredClientCertificate()throws Exception{
        self("dns:localhost");Path identity=dir.resolve("identity");char[] password=Files.readString(identity.resolve("password")).toCharArray();
        KeyStore store=KeyStore.getInstance("PKCS12");try(InputStream in=Files.newInputStream(identity.resolve("server.p12"))){store.load(in,password);}
        Path pem=dir.resolve("server.key");Files.writeString(pem,"-----BEGIN PRIVATE KEY-----\n"+Base64.getMimeEncoder().encodeToString(store.getKey("server",password).getEncoded())+"\n-----END PRIVATE KEY-----\n");
        new TlsConfig(new TlsConfig.Options(true,null,"",null,"PKCS12","",identity.resolve("server.crt"),pem,null,false));
        Path jks=dir.resolve("server.jks");KeyStore legacy=KeyStore.getInstance("JKS");legacy.load(null,password);legacy.setKeyEntry("server",store.getKey("server",password),password,store.getCertificateChain("server"));try(OutputStream out=Files.newOutputStream(jks)){legacy.store(out,password);}
        new TlsConfig(new TlsConfig.Options(true,null,"",jks,"JKS",new String(password),null,null,null,false));
        Path clientStore=dir.resolve("client.p12");
        Process keytool=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/keytool").toString(),"-genkeypair","-alias","client","-keyalg","RSA","-keysize","2048","-dname","CN=HEC test client","-ext","EKU=clientAuth","-validity","1","-storetype","PKCS12","-keystore",clientStore.toString(),"-storepass","test-client-only","-noprompt").redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(keytool.waitFor(30,TimeUnit.SECONDS));assertEquals(0,keytool.exitValue());
        KeyStore clientIdentity=KeyStore.getInstance("PKCS12");try(InputStream in=Files.newInputStream(clientStore)){clientIdentity.load(in,"test-client-only".toCharArray());}
        Path clientCert=dir.resolve("client.crt");Files.write(clientCert,clientIdentity.getCertificate("client").getEncoded());
        TlsConfig mtls=new TlsConfig(new TlsConfig.Options(true,null,"",identity.resolve("server.p12"),"PKCS12",new String(password),null,null,clientCert,true));
        HttpClient noCert=HttpClient.newBuilder().sslContext(trust(identity.resolve("server.crt"),null,null)).build();
        try(var acks=new AckManager(dir);var server=new HecServer("127.0.0.1",0,mtls,Limits.defaults(),store(),acks,received::add)){
            server.start();assertThrows(IOException.class,()->post(noCert,"https://localhost:"+server.port(),"/services/collector/event","{}",ProtocolTest.SECRET));
            HttpClient authenticated=HttpClient.newBuilder().sslContext(trust(identity.resolve("server.crt"),clientIdentity,"test-client-only".toCharArray())).build();
            assertEquals(200,post(authenticated,"https://localhost:"+server.port(),"/services/collector/event","{\"event\":\"mTLS\"}",ProtocolTest.SECRET).statusCode());
        }
    }
}
