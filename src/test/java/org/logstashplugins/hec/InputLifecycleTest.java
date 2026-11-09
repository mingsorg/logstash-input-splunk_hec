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
    RecordingMetrics metrics=new RecordingMetrics();
    SplunkHec input()throws Exception{return input(Map.of());}
    SplunkHec input(Map<String,Object> extra)throws Exception{
        metrics=new RecordingMetrics();var instanceMetrics=metrics;
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
            (proxy,method,args)->switch(method.getName()){
                case "getLogger" -> LogManager.getLogger(InputLifecycleTest.class);
                case "getMetric" -> {assertEquals("lifecycle-test",((Plugin)args[0]).getId());yield instanceMetrics.namespace("");}
                default -> null;
            });
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
    @Test void selectedHttpAckIsDurableBeforeQueueAndBadSuffixPreservesEarlierRequest()throws Exception{
        var values=Map.<String,Object>of("s2s_line_breaker_rules_json",S2SAssemblyTest.RULES.replace(":100}",":60000}"),
            "tokens_json",new Password("[{\"token\":\""+ProtocolTest.SECRET+"\",\"useACK\":true}]"));
        var received=new LinkedBlockingQueue<Map<String,Object>>();var input=input(values);
        Thread running=Thread.ofVirtual().start(()->input.start(received::add));
        try{
            var server=server(input);var client=HttpClient.newHttpClient();
            var good=new S2STest.Body().meta().eventAt(0x0a,0,0,1).str("START pending").compressed();
            var response=assemblyPost(client,server.port(),"s2s",good);
            assertEquals(200,response.statusCode(),response.body());long ack=HecProtocol.JSON.readTree(response.body()).get("ackId").longValue();
            assertTrue(java.nio.file.Files.isRegularFile(directory.resolve("assembly/current-v3")));assertTrue(received.isEmpty());
            var poll=assemblyPost(client,server.port(),"ack",("{\"acks\":["+ack+"]}").getBytes());
            assertTrue(HecProtocol.JSON.readTree(poll.body()).path("acks").path(Long.toString(ack)).asBoolean());
            assertEquals(1L,metrics.snapshot().get("hec.http.ack.success"));
            assertEquals(1L,metrics.snapshot().get("hec.assembly.contributions"));
            assertEquals(0L,metrics.snapshot().get("hec.handoff.http_s2s.returned"));
            byte[] before=S2SAssemblyTest.durableBytes(directory.resolve("assembly"));
            byte[] malformed=new S2STest.Body().meta().eventAt(0x0a,0,13,1).str("trace").op(0xfb).compressed();
            var bad=assemblyPost(client,server.port(),"s2s",malformed);assertEquals(400,bad.statusCode());assertFalse(bad.body().contains("ackId"));
            assertArrayEquals(before,S2SAssemblyTest.durableBytes(directory.resolve("assembly")));
        }finally{input.stop();running.join(5000);}
        // Restart does not force a boundary; the accepted tail can receive a later request.
        var reopened=input(values);Thread restarted=Thread.ofVirtual().start(()->reopened.start(received::add));
        try{
            var server=server(reopened);assertTrue(received.isEmpty());
            var next=new S2STest.Body().meta().eventAt(0x0a,0,13,1).str("trace\nSTART next").compressed();
            assertEquals(200,assemblyPost(HttpClient.newHttpClient(),server.port(),"s2s",next).statusCode());
            var complete=received.poll(5,TimeUnit.SECONDS);assertNotNull(complete);assertEquals("START pending\ntrace\n",complete.get("event"));
        }finally{reopened.stop();restarted.join(5000);}
    }
    @Test void disabledRulesRejectRetainedV3WithoutLegacyMarkerMaskingDetection()throws Exception{
        var values=Map.<String,Object>of("s2s_line_breaker_rules_json",S2SAssemblyTest.RULES.replace(":100}",":60000}"));
        var input=input(values);Thread running=Thread.ofVirtual().start(()->input.start(event->{}));
        try{
            var good=new S2STest.Body().meta().eventAt(0x0a,0,0,1).str("START retained").compressed();
            assertEquals(200,assemblyPost(HttpClient.newHttpClient(),server(input).port(),"s2s",good).statusCode());
        }finally{input.stop();running.join(5000);}
        Path assembly=directory.resolve("assembly");
        // Remove the legacy marker so only current-v3 can trigger retained-state discovery.
        java.nio.file.Files.delete(assembly.resolve("state"));
        var before=new TreeMap<String,List<Byte>>();
        try(var files=java.nio.file.Files.list(assembly)){for(Path file:files.toList())before.put(file.getFileName().toString(),bytes(java.nio.file.Files.readAllBytes(file)));}
        assertThrows(Exception.class,()->input(Map.of("s2s_line_breaker_rules_json","[]")));
        var after=new TreeMap<String,List<Byte>>();
        try(var files=java.nio.file.Files.list(assembly)){for(Path file:files.toList())after.put(file.getFileName().toString(),bytes(java.nio.file.Files.readAllBytes(file)));}
        assertEquals(before,after,"disabled rules must fail without altering retained v3 files");
    }
    private static List<Byte> bytes(byte[] value){var result=new ArrayList<Byte>();for(byte item:value)result.add(item);return result;}
    /** With assembly enabled, unmatched/structured direct records still ACK only after successful queue insertion. */
    @Test void directRecordAckWaitsForQueueInsertionAndFailedInsertionIsNotAcknowledged()throws Exception{
        var values=Map.<String,Object>of("s2s_line_breaker_rules_json",S2SAssemblyTest.RULES.replace(":100}",":60000}"),"hec_metadata","none",
            "tokens_json",new Password("[{\"token\":\""+ProtocolTest.SECRET+"\",\"useACK\":true}]"));
        var input=input(values);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var fail=new java.util.concurrent.atomic.AtomicBoolean();
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        Thread running=Thread.ofVirtual().start(()->input.start(event->{
            entered.countDown();
            try{if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException("sink never released");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
            if(fail.get())throw new IllegalStateException("queue rejected");
            received.add(event);}));
        try{
            int port=server(input).port();var client=HttpClient.newHttpClient();
            byte[] unmatched=new S2STest.Body().op(0xfe).v(1).ns("source::s1").ns("host::h").ns("sourcetype::unmatched").ns("channel").v(0)
                .eventAt(0x0a,0,0,1).str("direct line").compressed();
            var pending=client.sendAsync(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/services/collector/s2s"))
                .timeout(Duration.ofSeconds(10)).header("Authorization","Splunk "+ProtocolTest.SECRET).header("X-Splunk-Request-Channel",HttpTlsTest.CHANNEL)
                .POST(HttpRequest.BodyPublishers.ofByteArray(unmatched)).build(),HttpResponse.BodyHandlers.ofString());
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            assertFalse(pending.isDone(),"must not be acknowledged while queue insertion is blocked");
            release.countDown();
            var response=pending.get(5,TimeUnit.SECONDS);assertEquals(200,response.statusCode(),response.body());
            assertTrue(response.body().contains("ackId"));assertEquals("direct line",received.poll(5,TimeUnit.SECONDS).get("event"));
            fail.set(true);
            byte[] second=new S2STest.Body().op(0xfe).v(1).ns("source::s2").ns("host::h").ns("sourcetype::unmatched").ns("channel").v(0)
                .eventAt(0x0a,0,0,1).str("rejected line").compressed();
            var rejected=assemblyPost(client,port,"s2s",second);
            assertEquals(503,rejected.statusCode(),rejected.body());assertFalse(rejected.body().contains("ackId"));
        }finally{release.countDown();input.stop();running.join(5000);}
    }
    /** Listener-level ordering: while a completed same-sender predecessor is still blocked in the queue, a direct record is neither inserted nor ACKed. */
    @Test void httpDirectRecordWaitsBehindBlockedSameSenderPredecessorAtTheListener()throws Exception{
        var values=Map.<String,Object>of("hec_metadata","none","s2s_line_breaker_rules_json",S2SAssemblyTest.RULES,
            "tokens_json",new Password("[{\"token\":\""+ProtocolTest.SECRET+"\",\"useACK\":true}]"));
        var input=input(values);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var first=new java.util.concurrent.atomic.AtomicBoolean(true);
        var order=new CopyOnWriteArrayList<String>();
        Thread running=Thread.ofVirtual().start(()->input.start(event->{
            if(first.getAndSet(false)){entered.countDown();try{if(!release.await(15,TimeUnit.SECONDS))throw new IllegalStateException("never released");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}}
            order.add((String)event.get("event"));}));
        try{
            int port=server(input).port();var client=HttpClient.newHttpClient();
            // Predecessor: a selected tail that completes by its 100 ms deadline and then blocks the queue.
            assertEquals(200,assemblyPost(client,port,"s2s",new S2STest.Body().meta().eventAt(0x0a,0,0,1).str("START predecessor").compressed()).statusCode());
            assertTrue(entered.await(10,TimeUnit.SECONDS));
            byte[] direct=new S2STest.Body().op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::unmatched").ns("channel").v(0)
                .eventAt(0x0a,0,0,1).str("direct").compressed();
            var pending=client.sendAsync(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/services/collector/s2s")).timeout(Duration.ofSeconds(20))
                .header("Authorization","Splunk "+ProtocolTest.SECRET).header("X-Splunk-Request-Channel",HttpTlsTest.CHANNEL)
                .POST(HttpRequest.BodyPublishers.ofByteArray(direct)).build(),HttpResponse.BodyHandlers.ofString());
            Thread.sleep(700);
            assertFalse(pending.isDone(),"direct record must not be ACKed while its predecessor is blocked");assertTrue(order.isEmpty(),order.toString());
            release.countDown();
            var response=pending.get(15,TimeUnit.SECONDS);assertEquals(200,response.statusCode(),response.body());assertTrue(response.body().contains("ackId"));
            assertEquals(List.of("START predecessor","direct"),order);
        }finally{release.countDown();input.stop();running.join(5000);}
    }
    /** One HTTP batch [direct, journaled orphan, direct] reaches the queue in wire order through the listener's own enqueue wiring. */
    @Test void httpMixedBatchReachesTheQueueInExactWireOrder()throws Exception{
        var input=input(Map.of("hec_metadata","none","s2s_line_breaker_rules_json",S2SAssemblyTest.RULES));
        var order=new CopyOnWriteArrayList<String>();Thread running=Thread.ofVirtual().start(()->input.start(event->order.add((String)event.get("event"))));
        try{
            int port=server(input).port();
            var body=new S2STest.Body().op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::unmatched").ns("channel").v(0)
                .op(0xfe).v(2).ns("source::file").ns("host::host").ns("sourcetype::test").ns("channel").v(0);
            body.op(0xfc).v(1).v(0x0a).v(7).v(0).v(1).v(1790000000).v(0).str("first-direct");
            body.op(0xfc).v(2).v(0x0a).v(7).v(0).v(2).v(1790000000).v(0).str("orphan-line");
            body.op(0xfc).v(1).v(0x0a).v(7).v(20).v(3).v(1790000000).v(0).str("second-direct");
            var response=assemblyPost(HttpClient.newHttpClient(),port,"s2s",body.compressed());assertEquals(200,response.statusCode(),response.body());
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(order.size()<3&&System.nanoTime()<until)Thread.sleep(25);
            assertEquals(List.of("first-direct","orphan-line","second-direct"),order);
        }finally{input.stop();running.join(5000);}
    }
    @Test void tcpDirectRecordWaitsBehindBlockedSameSenderPredecessorAndIsAckedAfterInsertion()throws Exception{
        int tcp=freePort();var input=input(Map.of("s2s_tcp_enabled",true,"s2s_tcp_port",(long)tcp,"hec_metadata","none","s2s_line_breaker_rules_json",S2SAssemblyTest.RULES));
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var first=new java.util.concurrent.atomic.AtomicBoolean(true);var order=new CopyOnWriteArrayList<String>();
        Thread running=Thread.ofVirtual().start(()->input.start(event->{
            if(first.getAndSet(false)){entered.countDown();try{if(!release.await(15,TimeUnit.SECONDS))throw new IllegalStateException("never released");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}}
            order.add((String)event.get("event"));}));
        try{
            try(Socket socket=connectTcp(tcp)){
                tcpHello(socket);S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000002","__s2s_capabilities","v4=1;pl=7"));
                socket.getOutputStream().write(new S2STest.Body().meta().op(0xfc).v(1).v(0x0e).v(7).v(0).v(1).v(1).v(1700000000).v(0).str("START predecessor").out.toByteArray());socket.getOutputStream().flush();
                assertEquals(0xfb,socket.getInputStream().read());assertEquals(1,socket.getInputStream().read());
            }
            assertTrue(entered.await(10,TimeUnit.SECONDS));
            try(Socket socket=connectTcp(tcp)){
                tcpHello(socket);S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000002","__s2s_capabilities","v4=1;pl=7"));
                socket.getOutputStream().write(new S2STest.Body().op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::unmatched").ns("channel").v(0)
                    .op(0xfc).v(1).v(0x0e).v(7).v(0).v(1).v(2).v(1700000000).v(0).str("direct").out.toByteArray());socket.getOutputStream().flush();
                var ack=CompletableFuture.supplyAsync(()->{try{return new int[]{socket.getInputStream().read(),socket.getInputStream().read()};}catch(Exception e){throw new CompletionException(e);}});
                Thread.sleep(700);
                assertFalse(ack.isDone(),"direct record must not be ACKed while its predecessor is blocked");assertTrue(order.isEmpty(),order.toString());
                release.countDown();
                assertArrayEquals(new int[]{0xfb,2},ack.get(15,TimeUnit.SECONDS));
                assertEquals(List.of("START predecessor","direct"),order);
            }
        }finally{release.countDown();input.stop();running.join(5000);}
    }
    private static HttpResponse<String> assemblyPost(HttpClient client,int port,String route,byte[] body)throws Exception{
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/services/collector/"+route))
            .timeout(Duration.ofSeconds(5)).header("Authorization","Splunk "+ProtocolTest.SECRET).header("X-Splunk-Request-Channel",HttpTlsTest.CHANNEL)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    @Test void httpFramingSelectsWireThenQueryThenTokenAndUnmatchedFallsBack()throws Exception{
        String rules="["+String.join(",",java.util.stream.Stream.of("token","query","wire").map(type->
            "{\"match\":\"exact\",\"sourcetype\":\""+type+"\",\"event_start_pattern\":\"^START\",\"flush_timeout_ms\":60000}").toList())+"]";
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        var input=input(Map.of("s2s_line_breaker_rules_json",rules,"hec_metadata","none","tokens_json",
            new Password("[{\"token\":\""+ProtocolTest.SECRET+"\",\"sourcetype\":\"token\"}]")));
        Thread running=Thread.ofVirtual().start(()->input.start(received::add));
        try{
            int port=server(input).port();var client=HttpClient.newHttpClient();
            // wire, query, expected effective type, selected (rather than standard LF framing)
            String[][] cases={{"","","token","yes"},{"","query","query","yes"},
                {"wire","query","wire","yes"},{"unmatched","query","unmatched","no"},{"","unmatched","unmatched","no"}};
            for(int i=0;i<cases.length;i++){
                var row=cases[i];var body=new S2STest.Body().op(0xfe).v(1).ns("source::source-"+i).ns("host::sender");
                if(row[0].isEmpty())body.v(0);else body.ns("sourcetype::"+row[0]);
                byte[] bytes=body.ns("channel").v(0).eventAt(0x0a,0,0,1).str("START one\n trace\nSTART two").compressed();
                String route="s2s"+(row[1].isEmpty()?"":"?sourcetype="+row[1]);
                var response=assemblyPost(client,port,route,bytes);assertEquals(200,response.statusCode(),response.body());
                List<String> text=new ArrayList<>();int count=row[3].equals("yes")?1:3;
                for(int n=0;n<count;n++){
                    var event=received.poll(5,TimeUnit.SECONDS);assertNotNull(event);
                    assertEquals(row[2],event.get("sourcetype"));assertEquals("source-"+i,event.get("source"));text.add((String)event.get("event"));
                }
                assertEquals(row[3].equals("yes")?List.of("START one\n trace\n"):List.of("START one"," trace","START two"),text);
            }
            assertNull(received.poll(200,TimeUnit.MILLISECONDS));
        }finally{input.stop();running.join(5000);assertFalse(running.isAlive());}
    }
    @Test void selectedTcpAckPrecedesQueueAndReconnectContinuesTheDurableTail()throws Exception{
        int tcp=freePort();var input=input(Map.of("s2s_tcp_enabled",true,"s2s_tcp_port",(long)tcp,
            "s2s_line_breaker_rules_json",S2SAssemblyTest.RULES.replace(":100}",":60000}")));
        var received=new LinkedBlockingQueue<Map<String,Object>>();Thread running=Thread.ofVirtual().start(()->input.start(received::add));
        try{
            for(int occurrence=0;occurrence<2;occurrence++)try(Socket socket=connectTcp(tcp)){
                tcpHello(socket);
                S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000002","__s2s_capabilities","v4=1;pl=7"));
                var record=new S2STest.Body().meta().op(0xfc).v(1).v(0x0e).v(7).v(occurrence==0?0:13).v(1).v(occurrence+1).v(1700000000).v(0)
                    .str(occurrence==0?"START pending":"trace\nSTART next");
                socket.getOutputStream().write(record.out.toByteArray());socket.getOutputStream().flush();
                assertEquals(0xfb,socket.getInputStream().read());assertEquals(occurrence+1,socket.getInputStream().read());
                if(occurrence==0){assertTrue(received.isEmpty());assertTrue(java.nio.file.Files.exists(directory.resolve("assembly/current-v3")));}
            }
            var event=received.poll(5,TimeUnit.SECONDS);assertNotNull(event);assertEquals("START pending\ntrace\n",event.get("event"));
        }finally{input.stop();running.join(5000);}
    }
    @Test void tokenRevocationRejectsNewTrafficButDoesNotDiscardAcceptedAssembly()throws Exception{
        Path policy=directory.resolve("reload.conf");
        java.nio.file.Files.writeString(policy,"[http://one]\ntoken = "+ProtocolTest.SECRET+"\nuseACK = true\n");
        var input=input(Map.of("inputs_conf",policy.toString(),"tokens_json",new Password("[]"),
            "s2s_line_breaker_rules_json",S2SAssemblyTest.RULES.replace(":100}",":5000}")));
        var received=new LinkedBlockingQueue<Map<String,Object>>();Thread running=Thread.ofVirtual().start(()->input.start(received::add));
        try{
            var server=server(input);var client=HttpClient.newHttpClient();
            var bytes=new S2STest.Body().meta().eventAt(0x0a,0,0,1).str("START accepted").compressed();
            assertEquals(200,assemblyPost(client,server.port(),"s2s",bytes).statusCode());
            java.nio.file.Files.writeString(policy,"[http://one]\ntoken = replacement-token\nuseACK = true\n");
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);int status;
            do{status=assemblyPost(client,server.port(),"s2s",bytes).statusCode();if(status!=403)Thread.sleep(50);}while(status!=403&&System.nanoTime()<deadline);
            assertEquals(403,status);
            var accepted=received.poll(8,TimeUnit.SECONDS);assertNotNull(accepted);assertEquals("START accepted",accepted.get("event"));
            assertTrue(received.isEmpty());
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
    @Test void metadataMappingFailsStartupAtomicallyWithValueFreeDiagnostics()throws Exception{
        for(String bad:List.of("", "null", "[]", "42", "\"private-value\"", "{\"source\":1}",
            "{\"source\":null}", "{\"source\":true}", "{\"source\":{}}", "{\"source\":[]}",
            "{\"\":\"dest\"}", "{\" \t\":\"dest\"}", "{\"source\":\"\"}", "{\"source\":\" \"}",
            "{\"source\":\"a.b\"}", "{\"source\":\"[a]\"}", "{\"source\":\"1a\"}", "{\"source\":\"a-b\"}",
            "{\"source\":\"é\"}", "{\"source\":\"a\",\"source\":\"b\"}",
            "{\"source\":\"a\",\"sour\\u0063e\":\"b\"}",
             "{\"source\":\"a\",\"other\":\"a\"}", "{\"source\":\"a\"} {}", "{\"source\":\"a\"} trailing", "{",
             "{\"private-syntax-sentinel\":\"dest\", broken}",
             "{\"private-duplicate-sentinel\":\"one\",\"private-duplicate-sentinel\":\"two\"}")){
             var failure=assertThrows(IllegalArgumentException.class,()->input(Map.of("s2s_metadata_fields_json",bad)),bad);
             assertEquals("s2s_metadata_fields_json requires a JSON object of unique nonblank source names and unique simple destination identifiers ([A-Za-z_][A-Za-z0-9_]*) with string values",failure.getMessage());
            assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);
            assertFalse(failure.getMessage().contains("private-value"));
        }
        for(String good:List.of("{}", "{\"custom tenant.key[]\":\"_dest2\"}")){
            var input=input(Map.of("s2s_metadata_fields_json",good));
            try{assertTrue(input.configSchema().stream().anyMatch(s->s.name().equals("s2s_metadata_fields_json")));}finally{input.stop();}
        }
    }
    @Test void metadataMappingIsWiredIdenticallyThroughHttpAndTcpAndOversizeNeverAcks()throws Exception{
        for(boolean oversized:List.of(false,true))for(String mode:List.of("full","id_only","none")){
            int tcp=freePort();String value=oversized?"x".repeat(mode.equals("full")?2500:4096):"acme";
            var input=input(Map.of("state_directory",directory.resolve(mode+oversized).toString(),
                "s2s_tcp_enabled",true,"s2s_tcp_port",(long)tcp,"hec_metadata",mode,
                "max_event_bytes",4096L,"s2s_tcp_max_event_bytes",4096L,
                "tokens_json",new Password("[{\"token\":\""+ProtocolTest.SECRET+"\",\"useACK\":true}]"),
                "s2s_metadata_fields_json","{\"custom_tenant\":\"host\"}"));
            var events=Collections.synchronizedList(new ArrayList<Map<String,Object>>());
            Thread running=Thread.ofVirtual().start(()->input.start(events::add));
            try(Socket socket=connectTcp(tcp)){
                var body=new S2STest.Body().meta();
                // A fitting prefix must not be queued or acknowledged when a
                // later record makes the same HTTP batch invalid after mapping.
                if(oversized)body.event(0x23b,0).str("fitting prefix");
                var httpBody=body.event(0x23b,2).v(4).str("custom_tenant").str(value)
                    .v(3).str("host").v(42).str("one\ntwo").compressed();
                var response=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+server(input).port()+"/services/collector/s2s"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization","Splunk "+ProtocolTest.SECRET).header("X-Splunk-Request-Channel","12345678-1234-4234-8234-123456789abc")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(httpBody)).build(),HttpResponse.BodyHandlers.ofString());
                tcpHello(socket);
                S2STcpProtocol.writeFrame(socket.getOutputStream(),Map.of("_guid","00000000-0000-4000-8000-000000000002","__s2s_capabilities","v4=1;pl=7"));
                socket.getOutputStream().write(new S2STest.Body().meta().op(0xfc).v(1).v(0x3f).v(7).v(100).v(1).v(5).v(1790000000)
                    .v(2).v(4).str("custom_tenant").str(value).v(3).str("host").v(42).str("one\ntwo").out.toByteArray());
                socket.getOutputStream().flush();
                if(oversized){
                    assertEquals(503,response.statusCode());assertFalse(HecProtocol.JSON.readTree(response.body()).has("ackId"));
                    assertEquals(-1,socket.getInputStream().read());assertTrue(events.isEmpty());
                }else{
                    assertEquals(200,response.statusCode());assertTrue(HecProtocol.JSON.readTree(response.body()).has("ackId"));
                    assertEquals(0xfb,socket.getInputStream().read());assertEquals(5,socket.getInputStream().read());assertEquals(4,events.size());
                    for(int i=0;i<2;i++){
                        var http=new LinkedHashMap<>(events.get(i));var classic=new LinkedHashMap<>(events.get(i+2));
                        assertEquals(Map.of("host","acme"),http.get("s2s_metadata"));assertEquals("host",http.get("host"));
                        assertEquals(Map.of("host",42L),http.get("fields"));
                        assertEquals(mode.equals("none"),!http.containsKey("@metadata"));
                        http.remove("@metadata");classic.remove("@metadata");assertEquals(http,classic);
                    }
                }
            }finally{input.stop();running.join(5000);}
        }
    }
}
