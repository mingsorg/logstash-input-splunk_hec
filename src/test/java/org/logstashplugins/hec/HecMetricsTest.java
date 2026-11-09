package org.logstashplugins.hec;

import co.elastic.logstash.api.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.lang.reflect.*;
import java.lang.reflect.Proxy;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class HecMetricsTest {
    @TempDir Path directory;
    final HecMetrics metrics=new HecMetrics();
    final RecordingMetrics recording=new RecordingMetrics();
    HecMetricsTest(){metrics.register(recording.namespace(""));}
    S2SAssemblyTest helper(){var helper=new S2SAssemblyTest();helper.directory=directory;return helper;}
    S2SStreamAssembler assembler(S2SAssemblyTest h,S2SAssemblyStore.Faults faults)throws Exception{
        return new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
            S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,faults,metrics);
    }
    static void until(java.util.function.BooleanSupplier condition)throws Exception{
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!condition.getAsBoolean()&&System.nanoTime()<deadline)Thread.sleep(5);
        assertTrue(condition.getAsBoolean());
    }
    @Test void fixedSchemaZeroLongsConcurrencySaturationAndReset()throws Exception{
        assertEquals(HecMetrics.SCHEMA.size(),recording.registered.size());
        for(var entry:recording.snapshot().entrySet())assertEquals(entry.getKey().endsWith("epoch_millis")?-1L:0L,entry.getValue());
        try(var executor=Executors.newVirtualThreadPerTaskExecutor()){
            var jobs=new ArrayList<Future<?>>();
            for(int t=0;t<32;t++)jobs.add(executor.submit(()->{for(int i=0;i<1000;i++)metrics.increment("assembly.contributions");}));
            for(var job:jobs)job.get(5,TimeUnit.SECONDS);
        }
        assertEquals(32000,metrics.value("assembly.contributions"));
        metrics.add("assembly.contributions",Long.MAX_VALUE);metrics.increment("assembly.contributions");
        assertEquals(Long.MAX_VALUE,metrics.value("assembly.contributions"));
        assertEquals(0,new HecMetrics().value("assembly.contributions"));
        assertEquals(HecMetrics.SCHEMA.stream().map(key->"hec."+key).collect(java.util.stream.Collectors.toSet()),recording.registered.keySet());
        var scalar=new HecMetrics.Scalar(Long.MAX_VALUE);
        assertEquals("gauge/number",scalar.getType());
        assertEquals(Long.toString(Long.MAX_VALUE),HecProtocol.JSON.writeValueAsString(scalar),"Node Stats must expose an exact numeric scalar, not bean fields");
    }
    @Test void actualCompactionsAreSeparatedFromInitialPublication()throws Exception{
        try(var store=new S2SAssemblyStore(directory.resolve("compact"),8192,b->{},metrics)){
            var state=new S2SStreamAssembler.State("configuration",Map.of(),List.of(),Map.of(),false);store.initialize(state);
            store.commit(state);
            assertEquals(1,metrics.value("store.publication.count"));assertEquals(0,metrics.value("store.compaction.count"));
            store.compact();
            assertEquals(2,metrics.value("store.publication.count"));assertEquals(1,metrics.value("store.compaction.count"));
            assertEquals(0,metrics.value("store.compaction.failures"));assertTrue(metrics.value("store.compaction.total_nanos")>0);
        }
    }
    @Test void everyRealBoundaryCountsOnlyItsCommittedReason()throws Exception{
        for(String reason:List.of("metadata_conflict","coordinate_gap_or_reordering","reordering")){
            var h=helper();h.directory=directory.resolve(reason);Files.createDirectories(h.directory);var local=new HecMetrics();
            try(var assembly=new S2SStreamAssembler(h.directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                    S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{},local)){
                h.accept(assembly,"one",h.event("a",0,"START prior"));
                var continuation=h.event("a",reason.equals("coordinate_gap_or_reordering")?99:11,"trace",reason.equals("metadata_conflict")?Map.of("k","v"):Map.of(),false);
                if(reason.equals("reordering"))continuation=new S2SDecoder.Event(continuation.host(),continuation.source(),continuation.sourcetype(),continuation.channel(),continuation.index(),
                    continuation.flags(),continuation.stream(),continuation.offset(),0,continuation.seconds(),continuation.time(),continuation.dateParts(),continuation.timezone(),continuation.header(),continuation.fields(),continuation.meta(),continuation.raw());
                h.accept(assembly,"two",continuation);
                assertEquals(1,local.value("assembly.flush."+reason),reason);
                assertEquals(0,local.value("assembly.flush.timeout"));assertEquals(0,local.value("assembly.flush.new_start"));
            }
        }
    }
    @Test void successfulHandoffThenRemovalFailureCountsAgainWhenReplayed()throws Exception{
        var h=helper();var fail=new AtomicBoolean();
        try(var assembly=assembler(h,b->{if(fail.get()&&b.equals("append-header"))throw new IOException("removal failed");})){
            h.accept(assembly,"one",h.event("a",0,"orphan"));fail.set(true);assembly.start(e->{});
            until(()->!assembly.healthy());
            assertEquals(1,metrics.value("handoff.outbox.returned"));assertEquals(1,metrics.value("store.commit.failures"));
            assertEquals(1,metrics.value("assembly.outbox"));assertEquals(1,metrics.value("assembly.blocked"));
        }
        var reset=new HecMetrics();
        try(var assembly=new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{},reset)){
            assembly.start(e->{});until(()->reset.value("assembly.outbox")==0);
            assertEquals(1,reset.value("handoff.outbox.returned"));assertEquals(0,reset.value("assembly.contributions"));
        }
    }
    @Test void disabledMissingAndFaultingCollectorsNeverControlIngestion()throws Exception{
        AtomicInteger lookups=new AtomicInteger(),warnings=new AtomicInteger();
        Context context=(Context)Proxy.newProxyInstance(Context.class.getClassLoader(),new Class<?>[]{Context.class},(p,m,a)->{
            lookups.incrementAndGet();throw new IllegalStateException("reporter failed");});
        assertSame(HecMetrics.NONE,HecMetrics.create(false,context,null,s->warnings.incrementAndGet()));assertEquals(0,lookups.get());
        var local=HecMetrics.create(true,context,null,s->{warnings.incrementAndGet();throw new IllegalStateException("logger failed");});
        AtomicInteger returned=new AtomicInteger();local.handoff("tcp",e->returned.incrementAndGet(),Map.of());
        assertEquals(1,returned.get());assertEquals(1,local.value("handoff.tcp.returned"));assertEquals(1,warnings.get());
        HecMetrics.NONE.register(null);HecMetrics.NONE.increment("unused");
        var inputHelper=new InputLifecycleTest();inputHelper.directory=directory;
        try(var input=new InputClose(inputHelper.input(Map.of("enable_metric",false)))){assertTrue(inputHelper.metrics.registered.isEmpty());}
        NamespacedMetric broken=(NamespacedMetric)Proxy.newProxyInstance(NamespacedMetric.class.getClassLoader(),new Class<?>[]{NamespacedMetric.class},
            (p,m,a)->{throw new IllegalStateException("registration failed");});
        Context missing=(Context)Proxy.newProxyInstance(Context.class.getClassLoader(),new Class<?>[]{Context.class},(p,m,a)->broken);
        var fault=HecMetrics.create(true,missing,null,s->warnings.incrementAndGet());fault.increment("assembly.contributions");
        assertEquals(1,fault.value("assembly.contributions"));assertEquals(2,warnings.get());
        Context absent=(Context)Proxy.newProxyInstance(Context.class.getClassLoader(),new Class<?>[]{Context.class},(p,m,a)->null);
        assertDoesNotThrow(()->HecMetrics.create(true,absent,null,s->{}));
        var registrations=new AtomicInteger();var partial=new RecordingMetrics();
        Context interrupted=(Context)Proxy.newProxyInstance(Context.class.getClassLoader(),new Class<?>[]{Context.class},
            (p,m,a)->partialCollector(partial.namespace(""),registrations));
        var interruptedMetrics=HecMetrics.create(true,interrupted,null,s->warnings.incrementAndGet());
        interruptedMetrics.handoff("tcp",e->returned.incrementAndGet(),Map.of());
        assertEquals(3,partial.registered.size());assertEquals(3,warnings.get());assertEquals(1,interruptedMetrics.value("handoff.tcp.returned"));
    }
    static NamespacedMetric partialCollector(NamespacedMetric delegate,AtomicInteger calls){
        return (NamespacedMetric)Proxy.newProxyInstance(NamespacedMetric.class.getClassLoader(),new Class<?>[]{NamespacedMetric.class},(p,m,a)->{
            if(m.getName().equals("register")&&calls.incrementAndGet()==4)throw new IllegalStateException("partial collector");
            Object result=m.invoke(delegate,a);return result instanceof NamespacedMetric namespace?partialCollector(namespace,calls):result;
        });
    }
    @Test void acceptedHttpRequestWithLostReplyHasOnlyOneProcessingOutcome()throws Exception{
        var http=new HttpTlsTest();http.dir=directory;
        try(var resources=new IngressResources(Limits.defaults());var acks=new AckManager(directory);
            var server=new HecServer("127.0.0.1",0,http.plain(),Limits.defaults(),new TokenStore(null,ProtocolTest.INLINE,s->{}),acks,e->{},resources)){
            resources.metrics=metrics;
            String body="{\"event\":\"accepted\"}";
            byte[] request=("POST /services/collector/event HTTP/1.1\r\nHost: localhost\r\nAuthorization: Splunk "+ProtocolTest.SECRET+"\r\nContent-Length: "+body.length()+"\r\n\r\n"+body).getBytes();
            Socket broken=new Socket(){@Override public InputStream getInputStream(){return new ByteArrayInputStream(request);}
                @Override public OutputStream getOutputStream()throws IOException{throw new IOException("reply lost");}};
            resources.connections.acquire();
            var handle=HecServer.class.getDeclaredMethod("handle",Socket.class);handle.setAccessible(true);handle.invoke(server,broken);
            assertEquals(1,metrics.value("http.event.success"));assertEquals(0,metrics.value("http.event.internal"));assertEquals(0,metrics.value("http.event.busy"));
            assertEquals(1,metrics.value("handoff.http_event.returned"));assertEquals(2,metrics.value("http.response_failures"));assertEquals(0,metrics.value("handoff.active"));
            byte[] interim=new String(request).replace("Content-Length:","Expect: 100-continue\r\nContent-Length:").getBytes();
            Socket expired=new Socket(){@Override public InputStream getInputStream(){return new ByteArrayInputStream(interim);}
                @Override public OutputStream getOutputStream()throws IOException{throw new IOException("closed before interim response");}};
            resources.connections.acquire();handle.invoke(server,expired);
            assertEquals(4,metrics.value("http.response_failures"));assertEquals(1,metrics.value("http.event.internal"));assertEquals(1,metrics.value("handoff.http_event.returned"));
        }
    }
    @Test void acceptedTcpRecordWithLostAckRemainsDataSuccess()throws Exception{
        var tcp=new TcpServerTest();tcp.dir=directory;
        var bytes=new ByteArrayOutputStream();var hello=new byte[400];
        System.arraycopy(S2STcpProtocol.SIGNATURE.getBytes(),0,hello,0,S2STcpProtocol.SIGNATURE.length());
        System.arraycopy("metrics-probe".getBytes(),0,hello,128,13);
        System.arraycopy("8089".getBytes(),0,hello,384,4);bytes.write(hello);
        S2STcpProtocol.writeFrame(bytes,Map.of("__s2s_capabilities","ack=1;compression=0"));
        S2STcpProtocol.writeFrame(bytes,Map.of("_guid","00000000-0000-4000-8000-000000000001","__s2s_capabilities","v4=1;pl=7"));bytes.write(tcp.record(1,"accepted"));
        try(var resources=new IngressResources(tcp.limits);var server=new S2STcpServer("127.0.0.1",0,tcp.plain(),tcp.limits,resources,e->{},"main",Set.of(),s->{})){
            resources.metrics=metrics;var output=new ByteArrayOutputStream();
            Socket broken=new Socket(){@Override public InputStream getInputStream(){return new ByteArrayInputStream(bytes.toByteArray());}
                @Override public InetAddress getInetAddress(){return InetAddress.getLoopbackAddress();}
                @Override public OutputStream getOutputStream(){return new FilterOutputStream(output){@Override public void write(int value)throws IOException{if(value==0xfb)throw new IOException("ACK lost");out.write(value);}};}};
            resources.connections.acquire();
            var handle=S2STcpServer.class.getDeclaredMethod("handle",Socket.class);handle.setAccessible(true);handle.invoke(server,broken);
            assertEquals(1,metrics.value("tcp.data.success"));assertEquals(0,metrics.value("tcp.data.failure"));assertEquals(1,metrics.value("tcp.response_failures"));
            assertEquals(1,metrics.value("handoff.tcp.returned"));assertEquals(1,metrics.value("tcp.connection_failures"));assertEquals(1,metrics.value("tcp.connection_closed"));
        }
    }
    @Test void capacityGaugesIncludePositiveFinalizationReserveAndRefreshAfterRecovery()throws Exception{
        var h=helper();long quota=1<<20;
        try(var assembly=new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.FULL,
                S2SMetadataFields.EMPTY,"{}",quota,10,h.memory,s->{},h.clock::get,b->{},metrics)){
            h.accept(assembly,"one",h.event("a",0,"START first\n"+"trace\n".repeat(40)));
            long live=metrics.value("assembly.live_bytes"),reserve=metrics.value("assembly.reserved_bytes");
            assertTrue(reserve>0);assertEquals(assembly.liveBytes(),live);assertEquals(quota,metrics.value("assembly.quota_bytes"));
            assertEquals((live+reserve)*10000/quota,metrics.value("assembly.utilization_basis_points"));
        }
        var reset=new HecMetrics();
        try(var assembly=new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.FULL,
                S2SMetadataFields.EMPTY,"{}",quota,10,h.memory,s->{},h.clock::get,b->{},reset)){
            assertEquals(metrics.value("assembly.reserved_bytes"),reset.value("assembly.reserved_bytes"));
            h.expire(assembly);assertEquals(0,reset.value("assembly.reserved_bytes"));
            assertEquals(assembly.liveBytes()*10000/quota,reset.value("assembly.utilization_basis_points"));
        }
    }
    @Test void disabledAssemblyReplaysTheSameOutputsAndCacheDoesNotOwnDrainedState()throws Exception{
        var results=new ArrayList<List<Map<String,Object>>>();
        for(boolean enabled:List.of(true,false)){
            var h=helper();Path path=directory.resolve("assembly-"+enabled);var local=enabled?new HecMetrics():HecMetrics.NONE;
            var outputs=Collections.synchronizedList(new ArrayList<Map<String,Object>>());
            try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                    S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{},local)){
                h.accept(assembly,"one",h.event("a",0,"orphan\nSTART first\ntrace\nSTART last"));h.expire(assembly);
                var calls=new AtomicInteger();assembly.start(e->{if(calls.incrementAndGet()==2)throw new IllegalStateException("queue failed");outputs.add(e);});until(()->!assembly.healthy());
            }
            try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                    S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{},local)){
                assembly.start(outputs::add);until(()->assembly.outputCount()==0);
                assertInstanceOf(java.lang.ref.WeakReference.class,HttpTlsTest.privateField(assembly,"measuredState"));
            }
            results.add(outputs);
        }
        assertEquals(results.get(0),results.get(1));assertEquals(3,results.get(0).size());
    }
    record InputClose(SplunkHec input) implements AutoCloseable {public void close(){input.stop();}}
    @Test void committedLinesRetriesOrphansFlushAndRecoveryHaveExactDeltas()throws Exception{
        var h=helper();
        try(var assembly=assembler(h,b->{})){
            h.accept(assembly,"one",h.event("a",0,"orphan\nSTART first\ntrace\nSTART next"));
            assertEquals(4,metrics.value("assembly.contributions"));assertEquals(1,metrics.value("assembly.flush.new_start"));
            assertEquals(2,metrics.value("assembly.outbox"));assertEquals(1,metrics.value("assembly.pending"));
            assertEquals(assembly.liveBytes(),metrics.value("assembly.live_bytes"));
            h.accept(assembly,"retry",h.event("a",0,"orphan\nSTART first\ntrace\nSTART next"));
            assertEquals(4,metrics.value("assembly.contributions"));assertEquals(1,metrics.value("store.commit.count"));
            h.expire(assembly);assertEquals(1,metrics.value("assembly.flush.timeout"));assertEquals(3,metrics.value("assembly.outbox"));
            // Sizing invokes completed(), but must never fabricate another finalization.
            assembly.accountedLiveBytes();assembly.accountedLiveBytes();assertEquals(1,metrics.value("assembly.flush.timeout"));
            assertTrue(metrics.value("last_durable_acceptance_epoch_millis")>0);assertTrue(metrics.value("last_commit_epoch_millis")>0);
        }
        var reset=new HecMetrics();
        try(var assembly=new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{},reset)){
            assertEquals(3,reset.value("assembly.outbox"));assertEquals(0,reset.value("assembly.contributions"));
            assertEquals(-1,reset.value("last_durable_acceptance_epoch_millis"));
            assembly.start(e->{});until(()->reset.value("assembly.outbox")==0);
            assertEquals(3,reset.value("handoff.outbox.returned"));assertEquals(0,reset.value("assembly.flush.timeout"));
        }
    }
    @Test void rollbackAndAppendFaultsDoNotCountContributionsOrFlushes()throws Exception{
        for(String boundary:List.of("append-header","append-payload","append-sync","append-durable","pointer-move","publication-durable")){
            var h=helper();h.directory=directory.resolve(boundary);Files.createDirectories(h.directory);
            var local=new HecMetrics();var fail=new AtomicBoolean();
            try(var assembly=new S2SStreamAssembler(h.directory.resolve("assembly"),S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,
                    S2SMetadataFields.EMPTY,"{}",1<<20,10,h.memory,s->{},h.clock::get,b->{if(fail.get()&&b.equals(boundary))throw new IOException("injected");},local)){
                fail.set(true);assertThrows(IOException.class,()->h.accept(assembly,"one",h.event("a",0,"START first\nSTART next")));
                assertEquals(1,local.value("store.commit.count"),boundary);assertEquals(1,local.value("store.commit.failures"),boundary);
                assertEquals(0,local.value("assembly.contributions"));assertEquals(0,local.value("assembly.flush.new_start"));
                assertEquals(1,local.value("assembly.blocked"));assertEquals(-1,local.value("last_commit_epoch_millis"));
                assertTrue(local.value("store.commit.total_nanos")>0);
                if(boundary.equals("append-durable"))assertTrue(Files.size(S2SAssemblyTest.journal(h.directory.resolve("assembly")))>0,"failed return does not prove no durable bytes");
            }
        }
        var h=helper();try(var assembly=assembler(h,b->{})){
            h.accept(assembly,"prior",h.event("a",0,"START prior"));
            var invalid=new S2SDecoder.Event("host","bad","test","channel","main",10,7,0,1,0,null,List.of(),null,List.of(),Map.of(),Map.of(),new byte[]{(byte)255});
            assertThrows(HecException.class,()->h.accept(assembly,"invalid",h.event("a",11,"START staged"),invalid));
            assertEquals(1,metrics.value("assembly.contributions"));assertEquals(0,metrics.value("assembly.flush.new_start"));assertEquals(1,metrics.value("store.commit.count"));
        }
    }
    @Test void quotaCommitAttemptIsTimedWithoutBlockingTheStore()throws Exception{
        try(var store=new S2SAssemblyStore(directory.resolve("store"),1,b->{},metrics)){
            var empty=new S2SStreamAssembler.State("configuration",Map.of(),List.of(),Map.of(),false);store.initialize(empty);
            assertThrows(IOException.class,()->store.commit(new S2SStreamAssembler.State("x".repeat(10000),Map.of(),List.of(),Map.of(),false)));
            assertEquals(1,metrics.value("store.commit.count"));assertEquals(1,metrics.value("store.commit.failures"));assertFalse(store.failed());
            assertThrows(IOException.class,()->store.validateCapacity(2,0));assertEquals(1,metrics.value("store.capacity.failures"));
        }
    }
    @Test void committedContributionsSurviveALaterInterruptedBarrier()throws Exception{
        var h=helper();try(var assembly=assembler(h,b->{})){
            h.accept(assembly,"prior",h.event("a",0,"START prior"));
            var failure=new AtomicReference<Throwable>();
            Thread blocked=Thread.ofVirtual().start(()->{
                try(var lease=h.memory.lease();var ordered=assembly.acceptOrdered(List.of(h.event("a",11,"START next"),h.event("a",21,"structured",Map.of(),true)),
                        h.token(),Map.of(),"next","http",h.limits,lease,null)){ordered.enqueue(e->{});}
                catch(Throwable error){failure.set(error);}
            });
            try{until(()->metrics.value("assembly.contributions")==2);assertTrue(blocked.isAlive());
                assertEquals(1,metrics.value("assembly.flush.new_start"));assertEquals(1,metrics.value("assembly.flush.structured_transition"));
                assertEquals(2,metrics.value("assembly.outbox"));assertEquals(0,metrics.value("handoff.assembly_direct.returned"));}
            finally{blocked.interrupt();blocked.join(5000);}
            assertInstanceOf(InterruptedException.class,failure.get());assertEquals(2,metrics.value("assembly.contributions"));
        }
    }
    @Test void directAssemblyCallsCountOnlyTheReturnedPrefixAndReleaseTheGate()throws Exception{
        var h=helper();try(var assembly=assembler(h,b->{});var lease=h.memory.lease()){
            var raw=new S2SDecoder.Event("host","a","unmatched","channel","main",10,7,0,1,0,null,List.of(),null,List.of(),Map.of(),Map.of(),"one\ntwo".getBytes());
            try(var ordered=assembly.acceptOrdered(List.of(raw),h.token(),Map.of(),"batch","http",h.limits,lease,null)){
                var calls=new AtomicInteger();assertThrows(IllegalStateException.class,()->ordered.enqueue(e->{if(calls.incrementAndGet()==2)throw new IllegalStateException("queue failed");}));
            }
            assertEquals(1,metrics.value("handoff.assembly_direct.returned"));assertEquals(1,metrics.value("handoff.assembly_direct.failures"));
            assertEquals(0,metrics.value("assembly.contributions"));assertEquals(0,metrics.value("handoff.active"));
        }
    }
    @Test void tcpPartialCallsRecordOutcomesAndControlsAreNotIngestion()throws Exception{
        var tcp=new TcpServerTest();tcp.dir=directory;var calls=new AtomicInteger();
        try(var resources=new IngressResources(tcp.limits);var server=new S2STcpServer("127.0.0.1",0,tcp.plain(),tcp.limits,resources,
                e->{if(calls.incrementAndGet()==2)throw new IllegalStateException("queue failed");},"main",Set.of(),s->{})){
            resources.metrics=metrics;server.start();
            try(Socket socket=tcp.connect(server.port(),null)){tcp.greeting(socket,true);socket.getOutputStream().write(tcp.record(2,"one\ntwo"));socket.getOutputStream().flush();assertEquals(-1,socket.getInputStream().read());}
            until(()->metrics.value("tcp.connection_closed")==1);
            assertEquals(1,metrics.value("tcp.data.failure"));assertEquals(1,metrics.value("tcp.control.success"));
            assertEquals(1,metrics.value("handoff.tcp.returned"));assertEquals(1,metrics.value("handoff.tcp.failures"));
            try(Socket socket=tcp.connect(server.port(),null)){tcp.greeting(socket,true);socket.getOutputStream().write(tcp.record(3,"one\ntwo"));socket.getOutputStream().flush();assertEquals(3,tcp.ack(socket));}
            until(()->metrics.value("tcp.connection_closed")==2);
            assertEquals(1,metrics.value("tcp.data.success"));assertEquals(2,metrics.value("tcp.control.success"));
            assertEquals(3,metrics.value("handoff.tcp.returned"));assertEquals(2,metrics.value("tcp.connection_accepted"));
            assertEquals(1,metrics.value("tcp.connection_failures"));assertEquals(0,metrics.value("assembly.contributions"));
        }
    }
    @Test void blockedFsyncAndQueueScrapesReadOnlyRegisteredAtomics()throws Exception{
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var block=new AtomicBoolean();var h=helper();
        try(var assembly=assembler(h,b->{if(block.get()&&b.equals("append-sync")){entered.countDown();try{assertTrue(release.await(5,TimeUnit.SECONDS));}catch(InterruptedException e){throw new IOException(e);}}})){
            block.set(true);
            var committing=CompletableFuture.runAsync(()->{try{h.accept(assembly,"one",h.event("a",0,"orphan"));}catch(Exception e){throw new CompletionException(e);}});
            try{assertTrue(entered.await(3,TimeUnit.SECONDS));assertTimeoutPreemptively(Duration.ofMillis(200),()->recording.snapshot());assertEquals(0,metrics.value("assembly.contributions"));}
            finally{release.countDown();}committing.get(5,TimeUnit.SECONDS);
            var queued=new CountDownLatch(1);var unblock=new CountDownLatch(1);
            assembly.start(e->{queued.countDown();try{unblock.await();}catch(InterruptedException x){Thread.currentThread().interrupt();throw HecException.busy();}});
            try{assertTrue(queued.await(3,TimeUnit.SECONDS));assertEquals(1,metrics.value("handoff.active"));
                assertTimeoutPreemptively(Duration.ofMillis(200),()->recording.snapshot());assertEquals(0,metrics.value("handoff.outbox.returned"));}
            finally{unblock.countDown();}until(()->metrics.value("assembly.outbox")==0);assertEquals(1,metrics.value("handoff.outbox.returned"));
        }
    }
    @Test void httpPartialFailuresAuthHealthAckAndUnknownRoutesAreSeparate()throws Exception{
        var http=new HttpTlsTest();http.dir=directory;var calls=new AtomicInteger();
        try(var resources=new IngressResources(Limits.defaults());var acks=new AckManager(directory);
            var server=new HecServer("127.0.0.1",0,http.plain(),Limits.defaults(),new TokenStore(null,ProtocolTest.INLINE,s->{}),acks,
                e->{if(calls.incrementAndGet()==2)throw new IllegalStateException("queue failed");},resources)){
            resources.metrics=metrics;server.start();String base="http://127.0.0.1:"+server.port();var client=http.client();
            assertEquals(503,http.post(client,base,"/services/collector/event","{\"event\":\"a\"}{\"event\":\"b\"}",ProtocolTest.SECRET).statusCode());
            assertEquals(1,metrics.value("handoff.http_event.returned"));assertEquals(2,metrics.value("handoff.http_event.count"));assertEquals(1,metrics.value("handoff.http_event.failures"));
            assertEquals(1,metrics.value("http.event.internal"));
            assertEquals(400,http.post(client,base,"/services/collector/event","{\"event\":\"prefix\"}broken",ProtocolTest.SECRET).statusCode());
            assertEquals(2,metrics.value("handoff.http_event.returned"));assertEquals(1,metrics.value("http.event.invalid"));
            assertEquals(403,http.post(client,base,"/services/collector/event","{}","wrong").statusCode());
            assertEquals(401,client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/event")).POST(HttpRequest.BodyPublishers.ofString("{}")).build(),HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(1,metrics.value("http.event.unauthorized"));assertEquals(1,metrics.value("http.event.forbidden"));
            assertEquals(200,client.send(HttpRequest.newBuilder(URI.create(base+"/services/collector/health")).build(),HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(1,metrics.value("http.health.success"));
            for(int i=0;i<5;i++)assertEquals(404,http.post(client,base,"/secret-"+i,"{}",ProtocolTest.SECRET).statusCode());
            assertEquals(5,metrics.value("http.unknown.invalid"));assertEquals(HecMetrics.SCHEMA.size(),recording.registered.size());
            assertEquals(0,metrics.value("handoff.active"));assertEquals(0,metrics.value("assembly.contributions"));
            // Deterministic response-writer failure, independently of successful queue handoffs.
            var respond=HecServer.class.getDeclaredMethod("respond",Socket.class,int.class,Map.class);respond.setAccessible(true);
            Socket broken=new Socket(){@Override public OutputStream getOutputStream()throws IOException{throw new IOException("write failed");}};
            assertThrows(InvocationTargetException.class,()->respond.invoke(server,broken,200,Map.of()));assertEquals(1,metrics.value("http.response_failures"));
        }
    }
}
