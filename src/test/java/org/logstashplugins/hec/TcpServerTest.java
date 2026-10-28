package org.logstashplugins.hec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

class TcpServerTest {
    @TempDir Path dir;
    final Limits limits=new Limits(16,64,10<<20,64<<20,512L<<20,8<<20,10000,100,10000,1000,3000);
    final List<Map<String,Object>> events=Collections.synchronizedList(new ArrayList<>());
    final List<String> diagnostics=Collections.synchronizedList(new ArrayList<>());
    TlsConfig plain()throws Exception{return new TlsConfig(new TlsConfig.Options(false,null,"",null,"PKCS12","",null,null,null,false));}
    TlsConfig tls()throws Exception{return new TlsConfig(new TlsConfig.Options(true,dir.resolve("identity"),"dns:localhost,ip:127.0.0.1",null,"PKCS12","",null,null,null,false));}
    SSLContext trusted(Path server,KeyManager[] keys)throws Exception{
        KeyStore trust=KeyStore.getInstance("PKCS12");trust.load(null,new char[0]);
        try(var input=Files.newInputStream(server)){trust.setCertificateEntry("server",CertificateFactory.getInstance("X.509").generateCertificate(input));}
        var managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());managers.init(trust);
        SSLContext context=SSLContext.getInstance("TLS");context.init(keys,managers.getTrustManagers(),new SecureRandom());return context;
    }
    Socket connect(int port,SSLContext context)throws Exception{
        Socket socket=context==null?new Socket("localhost",port):context.getSocketFactory().createSocket("localhost",port);
        socket.setSoTimeout(10000);
        if(socket instanceof SSLSocket ssl){var parameters=ssl.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");ssl.setSSLParameters(parameters);ssl.startHandshake();}
        return socket;
    }
    void greeting(Socket socket,boolean ack)throws Exception{
        byte[] header=new byte[400];
        System.arraycopy(S2STcpProtocol.SIGNATURE.getBytes(StandardCharsets.US_ASCII),0,header,0,S2STcpProtocol.SIGNATURE.length());
        System.arraycopy("test-sender".getBytes(),0,header,128,11);System.arraycopy("8089".getBytes(),0,header,384,4);
        socket.getOutputStream().write(header);
        S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("__s2s_capabilities","ack="+(ack?1:0)+";compression=0"));
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            var hello=S2STcpProtocol.frame(socket.getInputStream(),limits,memory);
            assertTrue(hello.pairs().get("__s2s_control_msg").contains("v4=true"));
        }
        S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000001","__s2s_capabilities","v4=1;pl=7"));
    }
    byte[] record(long id,String raw)throws Exception{
        return new S2STest.Body().meta().op(0xfc).v(1).v(0x3f).v(7).v(100).v(0).v(id).v(1790000000).v(0).str(raw).out.toByteArray();
    }
    long ack(Socket socket)throws Exception{
        assertEquals(0xfb,socket.getInputStream().read(),"expected single-ID ACK: "+diagnostics);
        long n=0;for(int shift=0;shift<70;shift+=7){int b=socket.getInputStream().read();if(b<0)throw new EOFException();n|=(long)(b&127)<<shift;if((b&128)==0)return n;}throw new IOException("invalid ACK");
    }
    String id(Map<String,Object> event){return String.valueOf(((Map<?,?>)((Map<?,?>)event.get("@metadata")).get("splunk_hec")).get("id"));}

    @Test void realCapturedUfHfReplayWorksOverPlainAndHostnameVerifiedTlsWithBothCompressionModes()throws Exception{
        TlsConfig secure=tls();SSLContext context=trusted(dir.resolve("identity/server.crt"),null);
        Map<String,List<String>> priorIds=new HashMap<>();int cases=0;
        for(boolean encrypted:List.of(false,true)){
            try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,encrypted?secure:plain(),limits,resources,events::add,"main",Set.of(),diagnostics::add)){
                server.start();
                for(String manifest:List.of("manifest.json","manifest-compressed.json"))for(var sample:HecProtocol.JSON.readTree(Files.readAllBytes(Path.of("tests/tcp/fixtures",manifest)))){
                    boolean source=sample.path("source_records").findValuesAsText("raw").stream().anyMatch(raw->!raw.isEmpty());
                    if(!source)continue;
                    byte[] bytes=Files.readAllBytes(Path.of("tests/tcp/fixtures",sample.path("client").asText()));
                    int first=400+4+ByteBuffer.wrap(bytes,400,4).getInt();int before=events.size();
                    try(Socket socket=connect(server.port(),encrypted?context:null)){
                        socket.getOutputStream().write(bytes,0,first);socket.getOutputStream().flush();
                        try(var memory=new MemoryBudget(limits.aggregate()).lease()){S2STcpProtocol.frame(socket.getInputStream(),limits,memory);}
                        socket.getOutputStream().write(bytes,first,bytes.length-first);socket.getOutputStream().flush();
                        for(var expected:sample.path("ids"))if(expected.longValue()!=0)assertEquals(expected.longValue(),ack(socket));
                    }
                    List<Map<String,Object>> actual=new ArrayList<>();
                    List<Map<String,Object>> snapshot;
                    synchronized(events){snapshot=new ArrayList<>(events.subList(before,events.size()));}
                    for(var event:snapshot)if(String.valueOf(event.get("source")).startsWith("/tmp/hec-source."))actual.add(event);
                    assertEquals(6,actual.size(),sample.path("hostname").asText()+" "+diagnostics);
                    List<String> ids=actual.stream().map(this::id).toList();
                    String key=sample.path("client").asText();if(encrypted)assertEquals(priorIds.get(key),ids);else priorIds.put(key,ids);
                    assertTrue(actual.stream().allMatch(e->!e.containsKey("message")));cases++;
                }
            }
        }
        assertEquals(8,cases);
    }
    @Test void failedInsertionNeverAcksAndReconnectReusesSourceCoordinateIds()throws Exception{
        AtomicInteger calls=new AtomicInteger();Consumer<Map<String,Object>> sink=e->{if(calls.incrementAndGet()==2)throw new IllegalStateException("queue failed");events.add(e);};
        try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,plain(),limits,resources,sink,"main",Set.of(),diagnostics::add)){
            server.start();
            try(Socket socket=connect(server.port(),null)){greeting(socket,true);socket.getOutputStream().write(record(2,"one\ntwo\n"));socket.getOutputStream().flush();assertEquals(-1,socket.getInputStream().read());}
            assertEquals(1,events.size());String first=id(events.getFirst());
            try(Socket socket=connect(server.port(),null)){greeting(socket,true);socket.getOutputStream().write(record(9,"one\ntwo\n"));socket.getOutputStream().flush();assertEquals(9,ack(socket));}
            assertEquals(3,events.size());assertEquals(first,id(events.get(1)));assertNotEquals(id(events.get(1)),id(events.get(2)));
        }
    }
    @Test void incompleteRecordIsClosedWithoutInsertionOrAck()throws Exception{
        try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,plain(),limits,resources,events::add,"main",Set.of(),diagnostics::add)){
            server.start();
            try(Socket socket=connect(server.port(),null)){greeting(socket,true);byte[] bytes=record(2,"incomplete");socket.getOutputStream().write(bytes,0,bytes.length-1);socket.getOutputStream().flush();socket.shutdownOutput();assertEquals(-1,socket.getInputStream().read());}
            assertTrue(events.isEmpty());
        }
    }
    @Test void ackDisabledDoesNotSendBinaryAcks()throws Exception{
        CountDownLatch inserted=new CountDownLatch(1);
        try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,plain(),limits,resources,e->{events.add(e);inserted.countDown();},"main",Set.of(),diagnostics::add)){
            server.start();
            try(Socket socket=connect(server.port(),null)){greeting(socket,false);socket.getOutputStream().write(record(2,"one\n"));socket.getOutputStream().flush();assertTrue(inserted.await(3,TimeUnit.SECONDS));socket.setSoTimeout(250);assertThrows(SocketTimeoutException.class,()->socket.getInputStream().read());}
            assertEquals(1,events.size());
        }
    }
    /** Latest TLS UF/HF were observed sending the F9/zlib stream while advertising compression=0. */
    @Test void recordStreamCompressionIsDeterminedByTheStreamWhenNotRequested()throws Exception{
        CountDownLatch inserted=new CountDownLatch(1);
        try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,plain(),limits,resources,e->{events.add(e);inserted.countDown();},"main",Set.of(),diagnostics::add)){
            server.start();
            try(Socket socket=connect(server.port(),null)){
                greeting(socket,true);
                socket.getOutputStream().write(0xf9);
                var deflater=new java.util.zip.DeflaterOutputStream(socket.getOutputStream(),new java.util.zip.Deflater(),true);
                deflater.write(record(2,"compressed\n"));deflater.flush();
                assertEquals(2,ack(socket));assertTrue(inserted.await(3,TimeUnit.SECONDS));
            }
            @SuppressWarnings("unchecked") var tcp=(Map<String,Object>)((Map<?,?>)((Map<?,?>)events.getFirst().get("@metadata")).get("splunk_hec")).get("tcp");
            assertEquals(false,tcp.get("compression_requested"));assertEquals(true,tcp.get("stream_compressed"));
        }
    }
    /** Real HF 10.6.1.1 retransmissions add tag 46: U(marker) S("resent") to the field list. */
    @Test void retransmittedRecordsWithTheObservedResentFieldAreDecodedAndUnknownDateTagsFailClosed()throws Exception{
        try(var resources=new IngressResources(limits);var server=new S2STcpServer("127.0.0.1",0,plain(),limits,resources,events::add,"main",Set.of(),diagnostics::add)){
            server.start();
            try(Socket socket=connect(server.port(),null)){
                greeting(socket,true);
                socket.getOutputStream().write(new S2STest.Body().meta().op(0xfc).v(1).v(0x3f).v(7).v(100).v(0).v(5).v(1790000000).v(1).v(0x46).v(0x45).str("resent").str("again\n").out.toByteArray());
                socket.getOutputStream().flush();assertEquals(5,ack(socket));
            }
            assertEquals(1,events.size());
            @SuppressWarnings("unchecked") var s2s=(Map<String,Object>)((Map<?,?>)((Map<?,?>)events.getFirst().get("@metadata")).get("splunk_hec")).get("s2s");
            assertEquals("again",events.getFirst().get("event"));
            assertFalse(events.getFirst().containsKey("fields")&&((Map<?,?>)events.getFirst().get("fields")).containsKey("resent"));
            assertEquals("resent",((Map<?,?>)s2s.get("wire_metadata")).get("resent"));
            // A tag in the date-part range that has not been observed must not be guessed.
            events.clear();
            try(Socket socket=connect(server.port(),null)){
                greeting(socket,true);
                socket.getOutputStream().write(new S2STest.Body().meta().op(0xfc).v(1).v(0x3f).v(7).v(100).v(0).v(6).v(1790000000).v(1).v(0x52).v(0).v(1).str("again\n").out.toByteArray());
                socket.getOutputStream().flush();assertEquals(-1,socket.getInputStream().read());
            }
            assertTrue(events.isEmpty());
        }
    }
    @Test void blockedTcpQueueAppliesSharedHttpBackpressureAndStopJoinsBoth()throws Exception{
        Limits bounded=new Limits(1,8,8192,16384,4<<20,4096,100,10,2000,40,1500);
        CountDownLatch inserted=new CountDownLatch(1),finished=new CountDownLatch(1);
        Consumer<Map<String,Object>> sink=e->{inserted.countDown();try{Thread.sleep(60000);}catch(InterruptedException stop){throw HecException.busy();}finally{finished.countDown();}};
        try(var resources=new IngressResources(bounded);var acks=new AckManager(dir);
            var http=new HecServer("127.0.0.1",0,plain(),bounded,new TokenStore(null,ProtocolTest.INLINE,s->{}),acks,sink,resources);
            var tcp=new S2STcpServer("127.0.0.1",0,plain(),bounded,resources,sink,"main",Set.of(),diagnostics::add)){
            http.start();tcp.start();
            try(Socket socket=connect(tcp.port(),null)){
                greeting(socket,true);socket.getOutputStream().write(record(2,"blocked\n"));socket.getOutputStream().flush();assertTrue(inserted.await(3,TimeUnit.SECONDS));
                var client=HttpClient.newHttpClient();String base="http://127.0.0.1:"+http.port();
                var health=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/health")).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
                assertEquals(503,health.statusCode());assertEquals(18,HecProtocol.JSON.readTree(health.body()).path("code").asInt());
                var post=client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/event")).timeout(Duration.ofSeconds(3)).header("Authorization","Splunk "+ProtocolTest.SECRET).POST(HttpRequest.BodyPublishers.ofString("{\"event\":\"busy\"}")).build(),HttpResponse.BodyHandlers.ofString());
                assertEquals(503,post.statusCode());socket.setSoTimeout(200);assertThrows(SocketTimeoutException.class,()->socket.getInputStream().read());
                long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);http.beginStop();tcp.beginStop();http.closeBy(deadline);tcp.closeBy(deadline);
                socket.setSoTimeout(1000);assertEquals(-1,socket.getInputStream().read());assertTrue(finished.await(1,TimeUnit.SECONDS));
            }
        }
    }
}
