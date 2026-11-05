package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class S2SAssemblyTest {
    @TempDir Path directory;
    static final String RULES="[{\"match\":\"exact\",\"sourcetype\":\"test\",\"event_start_pattern\":\"^START\",\"flush_timeout_ms\":100}]";
    final Limits limits=Limits.defaults();
    final MemoryBudget memory=new MemoryBudget(256L<<20);
    final AtomicLong clock=new AtomicLong(1000);
    TokenStore.Token token()throws Exception{return new TokenStore(null,ProtocolTest.INLINE,s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);}
    S2SStreamAssembler assembler()throws Exception{return assembler(MetadataMode.FULL,1<<20,10,RULES);}
    S2SStreamAssembler assembler(MetadataMode mode,long bytes,int streams,String rules)throws Exception{
        return new S2SStreamAssembler(directory.resolve("assembly"),S2SLineBreakerPolicy.parse(rules),mode,S2SMetadataFields.EMPTY,"{}",bytes,streams,memory,s->{},clock::get);
    }
    S2SDecoder.Event event(String source,long offset,String text){return event(source,offset,text,Map.of(),false);}
    S2SDecoder.Event event(String source,long offset,String text,Map<String,Object> fields,boolean structured){
        return new S2SDecoder.Event("host",source,"test","channel","main",structured?0x4a:0x0a,7,offset,1,1700000000,
            "1700000000.123456789",List.of(),null,List.of(),fields,Map.of(),text.getBytes(StandardCharsets.UTF_8));
    }
    List<Map<String,Object>> accept(S2SStreamAssembler assembly,String batch,S2SDecoder.Event... records)throws Exception{
        try(var lease=memory.lease()){return assembly.accept(List.of(records),token(),Map.of(),batch,"http",limits,lease,null);}
    }
    void expire(S2SStreamAssembler assembly)throws Exception{clock.addAndGet(101);try(var lease=memory.lease()){assembly.expire(lease);}}
    Map<String,Object> take(BlockingQueue<Map<String,Object>> received)throws Exception{var value=received.poll(3,TimeUnit.SECONDS);assertNotNull(value);return value;}
    @Test void strictPolicyAndExactThenOrderedGlobPrecedence(){
        String rules="[{\"match\":\"glob\",\"sourcetype\":\"t*\",\"event_start_pattern\":\"first\",\"flush_timeout_ms\":1},"+
            "{\"match\":\"glob\",\"sourcetype\":\"te??\",\"event_start_pattern\":\"second\",\"flush_timeout_ms\":2},"+
            "{\"match\":\"exact\",\"sourcetype\":\"test\",\"event_start_pattern\":\"exact\",\"flush_timeout_ms\":3}]";
        var policy=S2SLineBreakerPolicy.parse(rules);
        assertEquals(3,policy.select("test").timeout());assertEquals(1,policy.select("team").timeout());assertNull(policy.select("TEST"));
        for(String invalid:List.of("{}","null",RULES+"[]",RULES.replace("100","0"),RULES.replace("100","1.5"),
            RULES.replace("^START","(?<=secret)START"),RULES.replace("\"exact\"","\"regex\""),RULES.replace("\"test\"","\"\""),
            RULES.replace("\"match\":","\"match\":\"glob\",\"match\":"),RULES.replace("}]",",\"secret\":1}]"),RULES.replace("}]","},"+RULES.substring(1)))){
            var error=assertThrows(IllegalArgumentException.class,()->S2SLineBreakerPolicy.parse(invalid),invalid);
            assertFalse(error.getMessage().contains("secret"));assertNull(error.getCause());
        }
        var literal=S2SLineBreakerPolicy.parse(RULES.replace("test","t*?"));assertNotNull(literal.select("t*?"));assertNull(literal.select("team"));
        var unicode=S2SLineBreakerPolicy.parse(RULES.replace("\"exact\"","\"glob\"").replace("\"test\"","\"😀:*?\""));
        assertNotNull(unicode.select("😀:😀"));assertNotNull(unicode.select("😀:é\n"));assertNull(unicode.select("😀:"));
        // This catastrophic backtracking expression remains linear in RE2.
        assertFalse(S2SLineBreakerPolicy.parse(RULES.replace("^START","^(a+)+$ ")).select("test").start().matcher("a".repeat(100000)+"!").find());
    }
    @Test void crlfBlankLinesStrippedJoinsAndConcurrentSourceIsolation()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            assertTrue(accept(assembly,"one",event("a",0,"START a\r\n\r\n  trace")).isEmpty());
            assertTrue(accept(assembly,"two",event("b",0,"START b\nnext\n")).isEmpty());
            accept(assembly,"three",event("a",18,"tail")); // exact UTF-8 source length including CRLF
            expire(assembly);assembly.start(received::add);
            var values=List.of(take(received),take(received));
            assertEquals(Set.of("START a\r\n\r\n  trace\ntail","START b\nnext\n"),new HashSet<>(values.stream().map(e->(String)e.get("event")).toList()));
            assertEquals(Set.of("a","b"),new HashSet<>(values.stream().map(e->(String)e.get("source")).toList()));
            assertTrue(values.stream().allMatch(e->e.get("time").equals("1700000000.123456789")&&!e.containsKey("message")));
        }
    }
    @Test void orphanNewStartTimeoutAndLateContinuationAreDeterministic()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"orphan\nSTART one\ntrace\nSTART two"));
            assertEquals(2,assembly.outputCount());expire(assembly);assertEquals(3,assembly.outputCount());
            accept(assembly,"two",event("a",38,"late"));
            assembly.start(received::add);
            assertEquals("orphan",take(received).get("event"));
            var first=take(received);assertEquals("START one\ntrace\n",first.get("event"));assertEquals("new-start",reason(first));
            var second=take(received);assertEquals("START two",second.get("event"));assertEquals("timeout",reason(second));
            assertEquals("late",take(received).get("event"));
        }
    }
    static String reason(Map<String,Object> event){return (String)((Map<?,?>)((Map<?,?>)((Map<?,?>)event.get("@metadata")).get("splunk_hec")).get("assembly")).get("flush_reason");}
    @Test void metadataConflictGapReorderingAndStructuredTransitionDoNotOverwrite()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            accept(assembly,"1",event("a",0,"START first",Map.of("v",1L),false));
            accept(assembly,"2",event("a",11,"START second",Map.of("v",2L),false));
            accept(assembly,"3",event("a",100,"START gap",Map.of("v",2L),false));
            assembly.start(received::add);
            assertEquals("metadata-conflict",reason(take(received)));assertEquals("coordinate-gap-or-reordering",reason(take(received)));
            var direct=accept(assembly,"4",event("a",109,"structured\ntext",Map.of("v",3L),true));
            assertEquals("structured-transition",reason(take(received)));assertEquals("structured\ntext",direct.getFirst().get("event"));
            assertEquals(0,assembly.pendingCount());
        }
    }
    @Test void restartRetainsTailsReplayIdentityAndNativeNumericTypes()throws Exception{
        var fields=new LinkedHashMap<String,Object>();fields.put("int",new java.math.BigInteger("18446744073709551615"));fields.put("decimal",new java.math.BigDecimal("1.234567890123456789"));fields.put("zero",-0.0);
        String id;
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"START one",fields,false));
            assertEquals(1,assembly.pendingCount());
        }
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            assertEquals(1,assembly.pendingCount());assertEquals(0,assembly.outputCount());
            accept(assembly,"rebatch",event("a",0,"START one",fields,false));assertEquals(1,assembly.pendingCount());
            accept(assembly,"next",event("a",9,"trace",fields,false));expire(assembly);assembly.start(received::add);
            var output=take(received);assertEquals("START one\ntrace",output.get("event"));assertEquals(fields,output.get("fields"));
            assertEquals(HecProtocol.epochSeconds("1700000000.123456789"),output.get("@timestamp"));
            id=(String)((Map<?,?>)((Map<?,?>)output.get("@metadata")).get("splunk_hec")).get("id");assertTrue(id.startsWith("s2s-assembled-v1:"));
        }
        try(var assembly=assembler()){
            accept(assembly,"retry",event("a",9,"trace",fields,false));assertEquals(0,assembly.pendingCount());assertEquals(0,assembly.outputCount());
        }
    }
    @Test void positionlessBatchScopeAndRepeatedOccurrencesDoNotCollapse()throws Exception{
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",-1,"START same"),event("a",-1,"START same"));
            assertEquals(1,assembly.outputCount());assertEquals(1,assembly.pendingCount());
            accept(assembly,"one",event("a",-1,"START same"),event("a",-1,"START same"));assertEquals(1,assembly.outputCount());
            accept(assembly,"two",event("a",-1,"START same"));assertEquals(2,assembly.pendingCount());
        }
    }
    @Test void validationFailureRollsBackWholeBatchAndDefaultIdsRemainIdentical()throws Exception{
        try(var assembly=assembler()){
            accept(assembly,"prior",event("a",0,"START prior"));
            byte[] snapshot=Files.readAllBytes(directory.resolve("assembly/state"));
            var invalid=new S2SDecoder.Event("host","a","test","channel","forbidden",10,7,11,1,0,null,List.of(),null,List.of(),Map.of(),Map.of(),new byte[]{(byte)0xff});
            assertThrows(HecException.class,()->accept(assembly,"bad",event("b",0,"START bad"),invalid));
            assertArrayEquals(snapshot,Files.readAllBytes(directory.resolve("assembly/state")));
            var records=List.of(event("x",-1,"a\r\n\n b"),event("x",-1,"repeated"));
            try(var lease=memory.lease()){
                var unmatched=S2SLineBreakerPolicy.parse(RULES.replace("test","other"));
                try(var other=new S2SStreamAssembler(directory.resolve("other"),unmatched,MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",1<<20,10,memory,s->{},clock::get)){
                    var expected=new S2SEvents(limits,new HecProtocol(limits)).mapWithIdentity(records,token(),Map.of(),"batch",lease);
                    assertEquals(expected,other.accept(records,token(),Map.of(),"batch","http",limits,lease,null));
                }
            }
        }
    }
    @Test void quotasCorruptionTornWritesExclusiveLockAndConfigMismatchFailClosed()throws Exception{
        try(var assembly=assembler(MetadataMode.NONE,4096,1,RULES)){
            accept(assembly,"1",event("a",0,"START a"));byte[] before=Files.readAllBytes(directory.resolve("assembly/state"));
            assertThrows(HecException.class,()->accept(assembly,"2",event("b",0,"START b")));assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
            assertThrows(Exception.class,()->assembler());
            assertThrows(java.io.IOException.class,()->accept(assembly,"3",event("a",7,"x".repeat(3000))));assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
        }
        Files.writeString(directory.resolve("assembly/next"),"torn uncommitted write");
        try(var assembly=assembler(MetadataMode.NONE,4096,1,RULES)){assertEquals(1,assembly.pendingCount());}
        assertThrows(java.io.IOException.class,()->assembler(MetadataMode.FULL,4096,1,RULES));
        byte[] bytes=Files.readAllBytes(directory.resolve("assembly/state"));bytes[bytes.length-1]^=1;Files.write(directory.resolve("assembly/state"),bytes);
        assertThrows(java.io.IOException.class,()->assembler(MetadataMode.NONE,4096,1,RULES));
    }
    @Test void admissionReservesTaggedFinalizationBeforeAcknowledgingPendingData()throws Exception{
        String text="START first\n"+"trace\n".repeat(40);
        long pendingBytes,completedBytes;
        try(var probe=assembler()){
            accept(probe,"one",event("a",0,text));
            pendingBytes=Files.size(directory.resolve("assembly/state"))-65;
            expire(probe);completedBytes=Files.size(directory.resolve("assembly/state"))-65;
        }
        assertTrue(completedBytes>pendingBytes,"full tagged contribution output must exercise positive finalization growth");
        Path tight=directory.resolve("tight");
        try(var assembly=new S2SStreamAssembler(tight,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,
                S2SMetadataFields.EMPTY,"{}",pendingBytes,10,memory,s->{},clock::get)){
            assertThrows(java.io.IOException.class,()->accept(assembly,"one",event("a",0,text)));
            assertTrue(assembly.healthy());assertEquals(0,assembly.pendingCount());
            assertFalse(Files.exists(tight.resolve("state")),"reject before committing or ACKing a tail that cannot complete");
        }
        // An admitted snapshot can complete after restart with no handoff needed to make room.
        Path enough=directory.resolve("enough");long quota=completedBytes+512;
        try(var assembly=new S2SStreamAssembler(enough,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,
                S2SMetadataFields.EMPTY,"{}",quota,10,memory,s->{},clock::get)){
            accept(assembly,"one",event("a",0,text));assertEquals(1,assembly.pendingCount());
        }
        try(var assembly=new S2SStreamAssembler(enough,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,
                S2SMetadataFields.EMPTY,"{}",quota,10,memory,s->{},clock::get)){
            expire(assembly);assertEquals(0,assembly.pendingCount());assertEquals(1,assembly.outputCount());
            assertTrue(Files.size(enough.resolve("state"))<=quota+65);
        }
    }
    @Test void thousandLineEventFitsTheRequestBudgetWithoutRepeatedPrefixCharging()throws Exception{
        String text="START first\n"+"x".repeat(128).concat("\n").repeat(999);
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){
            accept(assembly,"many",event("a",0,text));
            expire(assembly);assertEquals(1,assembly.outputCount());assertTrue(assembly.healthy());
        }
    }
    @Test void smallQuotaReceiptHistoryCannotFillAnOtherwiseDrainedStore()throws Exception{
        for(int run=0;run<2;run++)try(var assembly=assembler(MetadataMode.NONE,4096,10,RULES)){
            var received=new LinkedBlockingQueue<Map<String,Object>>();assembly.start(received::add);
            for(int i=0;i<80;i++){
                accept(assembly,"run"+run+"-"+i,event("a",run*1000L+i,"orphan"));
                assertEquals("orphan",take(received).get("event"));
            }
            assertTrue(assembly.healthy());assertEquals(0,assembly.pendingCount());
        }
    }
    @Test void blockedQueueStopRetainsOutboxAndReplaysAfterHandoffWindow()throws Exception{
        var entered=new CountDownLatch(1);var handed=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"START a"));expire(assembly);
            assembly.start(event->{handed.add(event);entered.countDown();try{Thread.sleep(60000);}catch(InterruptedException stop){throw HecException.busy();}});
            assertTrue(entered.await(3,TimeUnit.SECONDS));assertEquals(1,assembly.outputCount());
        }
        var original=take(handed);
        try(var assembly=assembler()){
            assembly.start(handed::add);assertEquals(original,take(handed));
        }
        assertEquals(0,memory.used());
    }
    @Test void durableOversizeBlockSurvivesRestartWithoutTruncatingAcceptedTail()throws Exception{
        Limits small=new Limits(1,1,4096,4096,8L<<20,1024,100,100,1000,1000,1000);
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){
            try(var lease=memory.lease()){
                assembly.accept(List.of(event("a",0,"START "+"x".repeat(600))),token(),Map.of(),"one","http",small,lease,null);
                assertThrows(HecException.class,()->assembly.accept(List.of(event("a",606,"x".repeat(600))),token(),Map.of(),"two","http",small,lease,null));
            }
            assertFalse(assembly.healthy());expire(assembly);assertEquals(1,assembly.pendingCount());assertEquals(0,assembly.outputCount());
        }
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){assertFalse(assembly.healthy());assertEquals(1,assembly.pendingCount());}
    }
    @Test void concurrentStreamsRemainIsolatedUnderInterleavedCommits()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler();var executor=Executors.newVirtualThreadPerTaskExecutor()){
            var start=new CountDownLatch(1);List<Future<?>> tasks=new ArrayList<>();
            for(int i=0;i<8;i++){String source="source-"+i;
                tasks.add(executor.submit(()->{start.await();accept(assembly,source+"1",event(source,0,"START "+source));
                    accept(assembly,source+"2",event(source,("START "+source).length(),"trace "+source));return null;}));
            }
            start.countDown();for(var task:tasks)task.get(5,TimeUnit.SECONDS);expire(assembly);assembly.start(received::add);
            Set<String> sources=new HashSet<>();
            for(int i=0;i<8;i++){var output=take(received);String source=(String)output.get("source");sources.add(source);
                assertEquals("START "+source+"\ntrace "+source,output.get("event"));}
            assertEquals(8,sources.size());
        }
    }
    @Test void failedDiskWriteNeverCommitsTheNewContributionAndDiagnosesBlockedHealth()throws Exception{
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"START retained"));byte[] before=Files.readAllBytes(directory.resolve("assembly/state"));
            Files.createDirectory(directory.resolve("assembly/next")); // write failure at the actual journal I/O boundary
            assertThrows(java.io.IOException.class,()->accept(assembly,"two",event("a",14,"trace")));
            assertFalse(assembly.healthy());assertNotNull(assembly.failure());assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
        }
        Files.delete(directory.resolve("assembly/next")); // repair injected storage failure, not accepted state
        try(var assembly=assembler()){assertEquals(1,assembly.pendingCount());}
    }
    @Test void deadlineAppliesBeforeLateContinuationEvenWhenTheWorkerHasNotRun()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"START retained"));clock.addAndGet(101);
            accept(assembly,"two",event("a",14,"late"));assembly.start(received::add);
            assertEquals("START retained",take(received).get("event"));assertEquals("late",take(received).get("event"));
        }
    }
    @Test void emptyNativeRecordIsABlankLogicalLineAndUtf8CoordinatesAreRetained()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            accept(assembly,"one",event("a",0,"START é"));
            accept(assembly,"two",event("a",8,""),event("a",8,""));
            accept(assembly,"two",event("a",8,""),event("a",8,"")); // exact-batch retry does not add blanks
            accept(assembly,"three",event("a",8,"trace"));expire(assembly);assembly.start(received::add);
            var output=take(received);assertEquals("START é\n\n\ntrace",output.get("event"));
            var provenance=(Map<?,?>)((Map<?,?>)((Map<?,?>)output.get("@metadata")).get("splunk_hec")).get("assembly");
            var contributions=(List<?>)provenance.get("contributions");
            assertEquals(8L,((Map<?,?>)contributions.getLast()).get("logical_offset"));
        }
    }
    @Test void invalidRawSuffixIsValidatedBeforeOversizePrefixCanBlockEarlierAcceptedState()throws Exception{
        Limits small=new Limits(1,1,4096,4096,8L<<20,1024,100,100,1000,1000,1000);
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES);var lease=memory.lease()){
            assembly.accept(List.of(event("a",0,"START "+"x".repeat(600))),token(),Map.of(),"prior","http",small,lease,null);
            byte[] before=Files.readAllBytes(directory.resolve("assembly/state"));
            var invalid=new S2SDecoder.Event("host","b","test","channel","main",10,7,0,1,0,null,List.of(),null,List.of(),Map.of(),Map.of(),new byte[]{(byte)0xff});
            var error=assertThrows(HecException.class,()->assembly.accept(List.of(event("a",606,"x".repeat(600)),invalid),token(),Map.of(),"invalid","http",small,lease,null));
            assertEquals(6,error.code);assertTrue(assembly.healthy());assertEquals(1,assembly.pendingCount());
            assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
            var conflict=assertThrows(HecException.class,()->assembly.accept(List.of(event("a",606,"x".repeat(600)),event("a",0,"changed retry")),token(),Map.of(),"conflicting","http",small,lease,null));
            assertEquals(6,conflict.code);assertTrue(assembly.healthy());
            assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
        }
    }
    @Test void oversizeStartAfterRetiredStreamDoesNotBlockUnrelatedDurableState()throws Exception{
        Limits small=new Limits(1,1,4096,4096,8L<<20,1024,100,100,1000,1000,1000);
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES);var lease=memory.lease()){
            assembly.accept(List.of(event("a",0,"START first")),token(),Map.of(),"prior","http",small,lease,null);
            // The gap retires the durable stream inside the staged batch; the oversize new stream is not durable.
            var error=assertThrows(HecException.class,()->assembly.accept(List.of(event("a",5000,"START "+"x".repeat(2000))),token(),Map.of(),"gap","http",small,lease,null));
            assertEquals(HecException.busy().code,error.code);
            assertTrue(assembly.healthy());assertEquals(1,assembly.pendingCount());assertEquals(0,assembly.outputCount());
        }
    }
    @Test void sameSenderOutputWaitsForDirectRecordWhileOtherSendersFlow()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            assembly.start(received::add);
            assertTrue(accept(assembly,"one",event("a",0,"START first")).isEmpty());
            var structured=event("a",11,"structured",Map.of("k","v"),true);
            try(var lease=memory.lease();
                var ordered=assembly.acceptOrdered(List.of(structured,event("a",40,"START second")),token(),Map.of(),"two","http",limits,lease,null)){
                // The barrier already delivered the completed predecessor before accept returned.
                assertEquals("START first",take(received).get("event"));
                assertEquals(1,ordered.events().size());
                clock.addAndGet(101); // "START second" is now timed out but must stay behind the direct record.
                try(var other=memory.lease()){assembly.accept(List.of(event("c",0,"START other")),token(),Map.of(),"x","other",limits,other,null);}
                clock.addAndGet(101);
                // A different sender is not held back by the gate.
                assertEquals("START other",take(received).get("event"));
                assertNull(received.poll(300,TimeUnit.MILLISECONDS));
                received.add(ordered.events().getFirst()); // the caller enqueues its direct record
            }
            assertEquals("structured",take(received).get("event"));
            assertEquals("START second",take(received).get("event"));
        }
    }
    @Test void structuredRecordWaitsForEarlierSameSenderOutputEvenWithoutOtherStateChange()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            assertTrue(accept(assembly,"one",event("a",0,"START first")).isEmpty());
            expire(assembly); // completed output is queued but the worker is not running yet
            assertEquals(1,assembly.outputCount());
            // A structured record from another source of the same sender changes no assembly state.
            var thrown=new CompletableFuture<List<Map<String,Object>>>();
            Thread.ofVirtual().start(()->{try{thrown.complete(accept(assembly,"two",event("z",0,"structured",Map.of("k","v"),true)));}catch(Throwable e){thrown.completeExceptionally(e);}});
            assertThrows(TimeoutException.class,()->thrown.get(300,TimeUnit.MILLISECONDS));
            assembly.start(received::add);
            assertEquals("START first",take(received).get("event"));
            assertEquals(1,thrown.get(3,TimeUnit.SECONDS).size());
        }
    }
    @Test void everyDirectSlotOrdersBothDirectionsIncludingIdenticalNoneModeOutputs()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){
            assembly.start(received::add);
            accept(assembly,"initial",event("a",0,"START same\n"));
            var records=List.of(event("a",11,"direct one",Map.of(),true),
                event("a",21,"START same\nSTART same\n"),event("a",43,"direct two",Map.of(),true),
                event("a",53,"START last"));
            try(var lease=memory.lease();var ordered=assembly.acceptOrdered(records,token(),Map.of(),"slots","http",limits,lease,null)){
                assertEquals("START same\n",take(received).get("event"));
                assertNull(received.poll(200,TimeUnit.MILLISECONDS));
                ordered.enqueue(received::add);
            }
            expire(assembly);
            List<String> remaining=new ArrayList<>();for(int i=0;i<5;i++)remaining.add((String)take(received).get("event"));
            assertEquals(List.of("direct one","START same\n","START same\n","direct two","START last"),remaining);
        }
    }
    @Test void directEnqueueFailureReleasesSenderGate()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler()){
            assembly.start(received::add);
            try(var lease=memory.lease();var ordered=assembly.acceptOrdered(
                    List.of(event("a",0,"direct",Map.of(),true),event("a",6,"START after")),token(),Map.of(),"failure","http",limits,lease,null)){
                assertThrows(IllegalStateException.class,()->ordered.enqueue(e->{throw new IllegalStateException("queue rejected");}));
            }
            expire(assembly);assertEquals("START after",take(received).get("event"));assertTrue(assembly.healthy());
        }
    }
    @Test void concurrentHttpRequestsWaitForSameSenderButHostFallbackSeparatesHosts()throws Exception{
        try(var assembly=assembler();var lease=memory.lease()){
            var first=event("a",0,"direct first",Map.of(),true);
            var second=new CompletableFuture<List<Map<String,Object>>>();
            try(var ordered=assembly.acceptOrdered(List.of(first),token(),Map.of(),"first","input/http:",limits,lease,null)){
                Thread.ofVirtual().start(()->{try(var request=memory.lease()){
                    second.complete(assembly.accept(List.of(event("a",12,"direct second",Map.of(),true)),token(),Map.of(),"second","input/http:",limits,request,null));
                }catch(Throwable error){second.completeExceptionally(error);}});
                assertThrows(TimeoutException.class,()->second.get(200,TimeUnit.MILLISECONDS));
                var other=new S2SDecoder.Event("other-host",first.source(),first.sourcetype(),first.channel(),first.index(),first.flags(),
                    first.stream(),first.offset(),first.sequence(),first.seconds(),first.time(),first.dateParts(),first.timezone(),first.header(),first.fields(),first.meta(),first.raw());
                try(var independent=assembly.acceptOrdered(List.of(other),token(),Map.of(),"other","input/http:",limits,lease,null)){
                    assertEquals("other-host",independent.events().getFirst().get("host"));
                }
            }
            assertEquals("direct second",second.get(3,TimeUnit.SECONDS).getFirst().get("event"));
        }
    }
    @Test void inputNamespacesKeepIdenticalNativeSourcesAndAssembledIdsSeparate()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler();var lease=memory.lease()){
            for(String scope:List.of("first/http","second/http"))
                assembly.accept(List.of(event("a",0,"START same")),token(),Map.of(),"batch",scope,limits,lease,null);
            assertEquals(2,assembly.pendingCount());expire(assembly);assembly.start(received::add);
            var first=take(received);var second=take(received);
            assertEquals(first.get("event"),second.get("event"));assertNotEquals(first.get("@metadata"),second.get("@metadata"));
        }
    }
    S2SDecoder.Event attributes(S2SDecoder.Event event,String index,List<S2SDecoder.DatePart> parts,String timezone,List<String> header){
        return new S2SDecoder.Event(event.host(),event.source(),event.sourcetype(),event.channel(),index,event.flags(),event.stream(),
            event.offset(),event.sequence(),event.seconds(),event.time(),parts,timezone,header,event.fields(),event.meta(),event.raw());
    }
    @Test void changedRetryHeaderTimezoneOrDatePartsConflictsBeforeAnyMutation()throws Exception{
        var original=event("a",0,"START first");
        try(var assembly=assembler()){
            accept(assembly,"one",original);byte[] before=Files.readAllBytes(directory.resolve("assembly/state"));
            for(var changed:List.of(attributes(original,"main",List.of(),null,List.of("changed")),
                    attributes(original,"main",List.of(),"UTC",List.of()),
                    attributes(original,"main",List.of(new S2SDecoder.DatePart(1,0x42,7)),null,List.of()))){
                var error=assertThrows(HecException.class,()->accept(assembly,"retry",changed));assertEquals(6,error.code);
                assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));assertTrue(assembly.healthy());
            }
        }
    }
    @Test void retryOfOldIndexCannotFinalizeNewIndexTail()throws Exception{
        var old=event("a",0,"START old");
        var policy=new TokenStore(null,ProtocolTest.INLINE.replace("\"indexes\":\"main\"","\"indexes\":\"main,changed\""),s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);
        try(var assembly=assembler();var lease=memory.lease()){
            assembly.accept(List.of(old),policy,Map.of(),"one","http",limits,lease,null);
            assembly.accept(List.of(attributes(event("a",9,"START new"),"changed",List.of(),null,List.of())),policy,Map.of(),"two","http",limits,lease,null);
            assertEquals(1,assembly.outputCount());assertEquals(1,assembly.pendingCount());
            byte[] before=Files.readAllBytes(directory.resolve("assembly/state"));
            assembly.accept(List.of(old),policy,Map.of(),"retry","http",limits,lease,null);
            assertArrayEquals(before,Files.readAllBytes(directory.resolve("assembly/state")));
            assertEquals(1,assembly.outputCount());assertEquals(1,assembly.pendingCount());
        }
    }
    @Test void legacyWireIdentityIsIndependentOfSelectedPositionlessOccurrenceScope()throws Exception{
        for(boolean structured:List.of(false,true)){
            var record=event("a",-1,"repeated",Map.of(),structured);
            try(var assembly=new S2SStreamAssembler(directory.resolve("identity-"+structured),S2SLineBreakerPolicy.parse(RULES.replace("test","other")),
                    MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",1<<20,10,memory,s->{},clock::get);var lease=memory.lease()){
                var expected=new S2SEvents(limits,new HecProtocol(limits)).mapWithIdentity(List.of(record),token(),Map.of(),"wire-digest",lease);
                for(String occurrence:List.of("first-occurrence","second-occurrence"))
                    try(var ordered=assembly.acceptOrdered(List.of(record),token(),Map.of(),"wire-digest",occurrence,"test/tcp",limits,lease,null)){
                        assertEquals(expected,ordered.events());
                    }
            }
        }
    }
    // R2: recovery must repeat admission's finalization-headroom proof under the quota now in force.
    @Test void recoveryRejectsRetainedStateThatCannotFinalizeUnderTheConfiguredQuota()throws Exception{
        String text="START first\n"+"trace\n".repeat(40);
        long pendingBytes,completedBytes;
        try(var probe=assembler()){
            accept(probe,"one",event("a",0,text));pendingBytes=Files.size(directory.resolve("assembly/state"))-65;
            expire(probe);completedBytes=Files.size(directory.resolve("assembly/state"))-65;
        }
        assertTrue(completedBytes>pendingBytes);
        Path path=directory.resolve("shrunk");long original=completedBytes+512;
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",original,10,memory,s->{},clock::get)){
            accept(assembly,"one",event("a",0,text));assertEquals(1,assembly.pendingCount());
        }
        byte[] before=Files.readAllBytes(path.resolve("state"));
        // The snapshot itself fits, but its completed form does not.
        var error=assertThrows(java.io.IOException.class,()->new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,
            S2SMetadataFields.EMPTY,"{}",pendingBytes,10,memory,s->{},clock::get));
        assertTrue(error.getMessage().contains("recovery bounds"),error.getMessage());
        assertArrayEquals(before,Files.readAllBytes(path.resolve("state")),"failed recovery must not alter retained state");
        // Fewer stream slots than the retained work also fails closed, and the original configuration still recovers it.
        assertThrows(java.io.IOException.class,()->new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,
            S2SMetadataFields.EMPTY,"{}",original,0,memory,s->{},clock::get));
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",original,10,memory,s->{},clock::get)){
            expire(assembly);assertEquals(1,assembly.outputCount());
        }
    }
    // R3: a tail that admission accepted must be readable after restart (Jackson's default 20M string limit must not apply).
    @Test void acknowledgedTailAboveJacksonDefaultStringLimitRecoversAfterRestart()throws Exception{
        var big=new Limits(16,64,10<<20,64<<20,128L<<20,21<<20,10_000,100,30_000,1_000,10_000);
        var budget=new MemoryBudget(8L<<30);
        long quota=60L<<20;
        String head="START "+"x".repeat(20_000_000);
        Path path=directory.resolve("large");
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",quota,2,budget,s->{},clock::get);
            var lease=budget.lease()){
            assembly.accept(List.of(event("a",0,head)),token(),Map.of(),"big","http",big,lease,null);
            assertEquals(1,assembly.pendingCount());
        }
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",quota,2,budget,s->{},clock::get)){
            assertEquals(1,assembly.pendingCount());
            clock.addAndGet(101);assembly.start(received::add);
            var value=received.poll(30,TimeUnit.SECONDS);assertNotNull(value);assertEquals(head.length()+0,((String)value.get("event")).length());
        }
    }
    // R4: an enabled rule that matches nothing must not turn a legacy-ignored record into a rejected batch.
    @Test void enabledRuleDoesNotRejectDelimiterOnlyRecordWithDisallowedIndex()throws Exception{
        var blank=new S2SDecoder.Event("host","a","test","channel","not-permitted",0x0a,7,0,1,1700000000,"1700000000.1",List.of(),null,List.of(),Map.of(),Map.of(),"\n".getBytes(StandardCharsets.UTF_8));
        try(var lease=memory.lease()){
            assertEquals(List.of(),new S2SEvents(limits,new HecProtocol(limits)).mapWithIdentity(List.of(blank),token(),Map.of(),"b",lease),"precondition: legacy ignores it");
        }
        try(var assembly=assembler()){
            assertTrue(accept(assembly,"b",blank).isEmpty());assertEquals(0,assembly.pendingCount());assertEquals(0,assembly.outputCount());
            // Non-empty data with the same disallowed index is still rejected exactly as before.
            var data=new S2SDecoder.Event("host","a","test","channel","not-permitted",0x0a,7,0,1,1700000000,"1700000000.1",List.of(),null,List.of(),Map.of(),Map.of(),"START x".getBytes(StandardCharsets.UTF_8));
            assertThrows(HecException.class,()->accept(assembly,"c",data));
        }
    }
    // R1 (contract): strict same-sender order while the process runs and the handoff succeeds.
    @Test void orphanAfterDirectRecordIsDeliveredInExactSenderOrder()throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){
            assembly.start(received::add);
            var records=List.of(event("a",0,"direct before",Map.of("k","v"),true),event("a",20,"orphan after"));
            try(var lease=memory.lease();var ordered=assembly.acceptOrdered(records,token(),Map.of(),"order","http",limits,lease,null)){
                assertNull(received.poll(300,TimeUnit.MILLISECONDS),"journaled output must stay behind the unenqueued direct record");
                ordered.enqueue(received::add);
            }
            assertEquals(List.of("direct before","orphan after"),List.of(take(received).get("event"),take(received).get("event")));
        }
    }
    // R1 (documented limit): after a stop/failure between the journal commit and the direct handoff, the journaled output is
    // delivered first and the retried direct record follows (at-least-once, no loss, no duplicate of the journaled output).
    @Test void failureOrRestartBeforeDirectHandoffIsAtLeastOnceWithoutLossOrDuplicates()throws Exception{
        var records=List.of(event("a",0,"direct before",Map.of("k","v"),true),event("a",20,"orphan after"));
        // Restart window: journal committed, direct never enqueued, process stops.
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES);var lease=memory.lease();
            var ordered=assembly.acceptOrdered(records,token(),Map.of(),"crash","http",limits,lease,null)){
            assertEquals(1,assembly.outputCount());
        }
        var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=assembler(MetadataMode.NONE,1<<20,10,RULES)){
            assertEquals(1,assembly.outputCount());assembly.start(received::add);
            assertEquals("orphan after",take(received).get("event"));
            // The sender was never ACKed, so it retries the identical batch: the direct record is delivered, the orphan is not repeated.
            try(var lease=memory.lease();var ordered=assembly.acceptOrdered(records,token(),Map.of(),"crash","http",limits,lease,null)){
                ordered.enqueue(received::add);
            }
            assertEquals("direct before",take(received).get("event"));
            assertNull(received.poll(300,TimeUnit.MILLISECONDS));
            assertEquals(0,assembly.outputCount());
        }
    }
    // A record the standard path ignores and that no rule selects is neither ordered nor gated nor persisted.
    @Test void legacyIgnoredUnselectedRecordCreatesNoGateStateOrBarrier()throws Exception{
        var blank=new S2SDecoder.Event("host","a","other","channel","main",0x0a,7,0,1,1700000000,"1700000000.1",List.of(),null,List.of(),Map.of(),Map.of(),"\n".getBytes(StandardCharsets.UTF_8));
        try(var assembly=assembler();var lease=memory.lease()){
            try(var ordered=assembly.acceptOrdered(List.of(blank),token(),Map.of(),"b","http",limits,lease,null)){assertTrue(ordered.events().isEmpty());}
            assertEquals(0,assembly.pendingCount());assertEquals(0,assembly.outputCount());
            assertFalse(Files.exists(directory.resolve("assembly/state")),"nothing changed, so nothing is committed");
        }
    }
}
