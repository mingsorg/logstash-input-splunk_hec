package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class S2SJournalTest {
    @TempDir Path directory;
    final MemoryBudget memory=new MemoryBudget(1L<<30);
    S2SStreamAssembler assembler(Path path,long quota,S2SAssemblyStore.Faults faults)throws Exception{
        return new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",quota,10,memory,s->{},()->1000,faults);
    }
    void accept(S2SStreamAssembler assembler,long offset,String text)throws Exception{
        accept(assembler,"source",offset,text,Limits.defaults());
    }
    void accept(S2SStreamAssembler assembler,String source,long offset,String text,Limits limits)throws Exception{
        var token=new TokenStore(null,ProtocolTest.INLINE,s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);
        var event=new S2SDecoder.Event("host",source,"test","channel","main",10,7,offset,1,1700000000,"1700000000.123456789",
            List.of(),null,List.of(),Map.of("zero",-0.0,"large",new java.math.BigInteger("18446744073709551615")),Map.of(),text.getBytes(StandardCharsets.UTF_8));
        try(var lease=memory.lease()){assembler.accept(List.of(event),token,Map.of(),"batch-"+source+offset,"http",limits,lease,null);}
    }
    S2SStreamAssembler.State recovered(Path path,long quota)throws Exception{
        try(var store=new S2SAssemblyStore(path,quota)){return S2SStreamAssembler.recoveryMapper(quota).readValue(store.recover(),S2SStreamAssembler.State.class);}
    }
    @Test void changedEventLimitRestartContinueRestartIsReplayable()throws Exception{
        Path path=directory.resolve("event-limit");long quota=1L<<20;
        try(var assembly=assembler(path,quota,point->{})){accept(assembly,0,"START");}
        var limits=new Limits(16,64,10<<20,64<<20,128L<<20,2<<20,10000,100,30000,1000,10000);
        try(var assembly=assembler(path,quota,point->{})){accept(assembly,"source",5,"tail",limits);}
        try(var assembly=assembler(path,quota,point->{})){assertEquals(1,assembly.pendingCount());assertEquals(assembly.liveBytes(),assembly.accountedLiveBytes());}
        var pending=recovered(path,quota).pending().values().iterator().next();assertEquals("START\ntail",pending.text().value());assertEquals(limits.event(),pending.eventLimit());
    }
    @Test void replacedPendingOrderMatchesTimeoutDeliveryAcrossRecovery()throws Exception{
        Path path=directory.resolve("order");long quota=1L<<20;
        try(var assembly=assembler(path,quota,point->{})){
            accept(assembly,"a",0,"START old",Limits.defaults());accept(assembly,"b",0,"START b",Limits.defaults());accept(assembly,"a",9,"START new",Limits.defaults());
            var expected=(S2SStreamAssembler.State)HttpTlsTest.privateField(assembly,"state");
            assertEquals(new ArrayList<>(expected.pending().keySet()),new ArrayList<>(recoveredCopy(path,quota).pending().keySet()));
        }
        Path reference=directory.resolve("reference");copy(path,reference);
        assertEquals(deliver(path,quota),deliver(reference,quota));
        var values=deliveredEvents;
        assertEquals(List.of("START old","START b","START new"),values);
    }
    List<String> deliveredEvents;
    List<Map<String,Object>> deliver(Path path,long quota)throws Exception{
        var clock=new java.util.concurrent.atomic.AtomicLong(1000);var received=new java.util.concurrent.LinkedBlockingQueue<Map<String,Object>>();
        var events=new ArrayList<Map<String,Object>>();
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",quota,10,memory,s->{},clock::get)){
            int count=assembly.pendingCount()+assembly.outputCount();clock.set(1101);try(var lease=memory.lease()){assembly.expire(lease);}assembly.start(received::add);
            for(int i=0;i<count;i++){var event=received.poll(3,java.util.concurrent.TimeUnit.SECONDS);assertNotNull(event);events.add(event);}
        }
        deliveredEvents=events.stream().map(event->(String)event.get("event")).toList();return events;
    }
    S2SStreamAssembler.State recoveredCopy(Path path,long quota)throws Exception{Path target=directory.resolve("copy-"+UUID.randomUUID());copy(path,target);return recovered(target,quota);}
    @Test void drainedHistoricalStateRestartsWithLoweredQuota()throws Exception{
        Path path=directory.resolve("drained");var clock=new java.util.concurrent.atomic.AtomicLong(1000);var received=new java.util.concurrent.LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",1L<<20,10,memory,s->{},clock::get)){
            accept(assembly,0,"START "+"x".repeat(30000));clock.set(1101);try(var lease=memory.lease()){assembly.expire(lease);}assembly.start(received::add);
            assertNotNull(received.poll(3,java.util.concurrent.TimeUnit.SECONDS));long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
            while(assembly.outputCount()!=0&&System.nanoTime()<deadline)Thread.sleep(1);assertEquals(0,assembly.outputCount());
        }
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",4096,10,memory,s->{},clock::get)){
            assertEquals(0,assembly.pendingCount());assertEquals(0,assembly.outputCount());assertTrue(assembly.healthy());accept(assembly,30006,"START small");
        }
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",4096,10,memory,s->{},clock::get)){assertEquals(1,assembly.pendingCount());}
    }
    @Test void nullRecoveredOutputEnvelopeFailsBeforePublication()throws Exception{
        Path path=directory.resolve("null-output");Files.createDirectories(path);
        String configuration=TokenStore.fingerprint("assembly-v2:"+S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES).fingerprint+":"+MetadataMode.FULL+":{}");
        var state=new S2SStreamAssembler.State(configuration,Map.of(),List.of(new S2SStreamAssembler.Output("id",null,null)),Map.of(),false);
        byte[] original=wrap(HecProtocol.JSON.writeValueAsBytes(state));Files.write(path.resolve("state"),original);
        assertThrows(IOException.class,()->assembler(path,1L<<20,point->{}));assertArrayEquals(original,Files.readAllBytes(path.resolve("state")));
    }
    @Test void saturatedReceiptAccountingDoesNotTraverseReceiptMap()throws Exception{
        Path path=directory.resolve("saturated");
        try(var assembly=assembler(path,8L<<20,point->{})){
            var prior=(S2SStreamAssembler.State)HttpTlsTest.privateField(assembly,"state");
            var values=new LinkedHashMap<String,String>();for(int i=0;i<4096;i++)values.put(String.format("%064x",i),"a".repeat(64));
            var visits=new java.util.concurrent.atomic.AtomicInteger();
            Map<String,String> tracked=new AbstractMap<>(){
                @Override public Set<Entry<String,String>> entrySet(){visits.incrementAndGet();return values.entrySet();}
                @Override public int size(){return values.size();}
            };
            var state=new S2SStreamAssembler.State(prior.configuration(),Map.of(),List.of(),tracked,false);
            var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);field.set(assembly,state);
            long exact=assembly.liveBytes();visits.set(0);long start=System.nanoTime();
            for(int i=0;i<500;i++)assertEquals(exact,assembly.accountedLiveBytes());
            assertEquals(0,visits.get(),"capacity must use exact cached SHA-256 receipt entry sizes");assertTrue(System.nanoTime()-start>0);
        }
    }
    @Test void fixedContributionsHaveBoundedTransactionBytesAndExactCachedCapacity()throws Exception{
        Path path=directory.resolve("scaling");long quota=8L<<20;
        try(var assembly=assembler(path,quota,boundary->{})){
            accept(assembly,0,"START é\"\n");long offset=10;
            long first=0,last=0;
            for(int i=0;i<500;i++){
                long before=Files.size(S2SAssemblyTest.journal(path));
                accept(assembly,offset,"line é\"\t");offset+="line é\"\t".getBytes(StandardCharsets.UTF_8).length;
                long bytes=Files.size(S2SAssemblyTest.journal(path))-before;
                if(i==0)first=bytes;last=bytes;
                assertTrue(bytes<4096,"transaction must contain only its suffix, not an accumulated event");
                if(i%50==0)assertEquals(assembly.liveBytes(),assembly.accountedLiveBytes(),"cached accounting must match exact serializer bytes");
            }
            assertTrue(Math.abs(first-last)<64,"fixed-size contributions remain fixed-size across growing prefixes");
            assertEquals(1,assembly.pendingCount());
        }
        var state=recovered(path,quota);assertEquals(501,state.pending().values().iterator().next().contributions().size());
    }
    @Test void arbitraryRequestsReplayAgainstReferenceAndRetriesDoNotAppend()throws Exception{
        Path path=directory.resolve("random");long quota=1L<<20;Random random=new Random(937);
        StringBuilder expected=new StringBuilder("START");long offset=5;
        try(var assembly=assembler(path,quota,boundary->{})){accept(assembly,0,"START");}
        for(int batch=0;batch<80;batch++){
            try(var assembly=assembler(path,quota,boundary->{})){
                for(int j=0,n=1+random.nextInt(5);j<n;j++){
                    String suffix="x".repeat(1+random.nextInt(16));long coordinate=offset;
                    accept(assembly,coordinate,suffix);expected.append('\n').append(suffix);offset+=suffix.length();
                    long before=Files.size(S2SAssemblyTest.journal(path));accept(assembly,coordinate,suffix);assertEquals(before,Files.size(S2SAssemblyTest.journal(path)));
                }
            }
            var state=recovered(path,quota);assertEquals(expected.toString(),state.pending().values().iterator().next().text().value());
        }
    }
    @Test void receiptEvictionAndReinsertionPreservesCommitOrderAcrossReplay()throws Exception{
        Path path=directory.resolve("receipts");long quota=4096;
        // NONE mode leaves enough room for the small quota's seven retained receipts.
        var token=new TokenStore(null,ProtocolTest.INLINE,s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);
        try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.NONE,S2SMetadataFields.EMPTY,"{}",quota,10,memory,s->{},()->1000)){
            var received=new java.util.concurrent.LinkedBlockingQueue<Map<String,Object>>();assembly.start(received::add);
            for(int i=0;i<7;i++){
                var event=new S2SDecoder.Event("host","source","test","channel","main",10,7,i,1,1700000000,null,List.of(),null,List.of(),Map.of(),Map.of(),"orphan".getBytes(StandardCharsets.UTF_8));
                try(var lease=memory.lease()){assembly.accept(List.of(event),token,Map.of(),"b"+i,"http",Limits.defaults(),lease,null);}
                assertNotNull(received.poll(3,java.util.concurrent.TimeUnit.SECONDS));
            }
            var records=new ArrayList<S2SDecoder.Event>();
            for(int coordinate:new int[]{7,0})records.add(new S2SDecoder.Event("host","source","test","channel","main",10,7,coordinate,1,1700000000,null,List.of(),null,List.of(),Map.of(),Map.of(),"orphan".getBytes(StandardCharsets.UTF_8)));
            try(var lease=memory.lease()){assembly.accept(records,token,Map.of(),"cycle","http",Limits.defaults(),lease,null);}
            assertNotNull(received.poll(3,java.util.concurrent.TimeUnit.SECONDS));assertNotNull(received.poll(3,java.util.concurrent.TimeUnit.SECONDS));
        }
        var state=recovered(path,quota);assertEquals(7,state.receipts().size());
        // Compare in-memory order from the final replay with explicit transaction order.
        byte[] bytes=S2SAssemblyTest.durableBytes(path);int position=0;List<String> order=null;
        while(position<bytes.length){int length=(int)ByteBuffer.wrap(bytes,position+16,8).getLong();var transaction=HecProtocol.JSON.readTree(bytes,position+88,length);
            if(transaction.get("receiptOrder")!=null&&!transaction.get("receiptOrder").isNull()){order=new ArrayList<>();for(var key:transaction.get("receiptOrder"))order.add(key.asText());}
            position+=88+length;
        }
        assertNotNull(order,"evicted then reinserted receipt requires an explicit order delta");assertEquals(order,new ArrayList<>(state.receipts().keySet()));
    }
    @Test void everyIncompleteHeaderAndPayloadSuffixTruncatesButCompleteCorruptionFails()throws Exception{
        Path original=directory.resolve("original");long quota=1L<<20;
        try(var assembly=assembler(original,quota,boundary->{})){accept(assembly,0,"START");}
        byte[] prefix=S2SAssemblyTest.durableBytes(original);
        try(var assembly=assembler(original,quota,boundary->{})){accept(assembly,5,"tail");}
        byte[] complete=S2SAssemblyTest.durableBytes(original);int record=complete.length-prefix.length;
        for(int length=0;length<record;length++){
            Path target=directory.resolve("torn-"+length);copy(original,target);
            Files.write(S2SAssemblyTest.journal(target),Arrays.copyOf(complete,prefix.length+length));
            try(var assembly=assembler(target,quota,boundary->{})){assertEquals(1,assembly.pendingCount());}
            assertArrayEquals(prefix,S2SAssemblyTest.durableBytes(target));
        }
        for(int index:new int[]{prefix.length,prefix.length+8,prefix.length+16,prefix.length+24,prefix.length+56,complete.length-1}){
            Path target=directory.resolve("corrupt-"+index);copy(original,target);byte[] corrupt=complete.clone();corrupt[index]^=1;
            Files.write(S2SAssemblyTest.journal(target),corrupt);
            assertThrows(IOException.class,()->assembler(target,quota,boundary->{}));assertArrayEquals(corrupt,S2SAssemblyTest.durableBytes(target));
        }
    }
    @Test void appendFaultsRetainAcknowledgedPrefixAndMayReplayUnacknowledgedCommit()throws Exception{
        for(String boundary:List.of("append-header","append-payload","append-sync","append-durable")){
            Path path=directory.resolve(boundary);var armed=new AtomicReference<String>();
            try(var assembly=assembler(path,1L<<20,point->{if(point.equals(armed.get()))throw new IOException("injected "+point);})){accept(assembly,0,"START");armed.set(boundary);
                assertThrows(IOException.class,()->accept(assembly,5,"tail"));assertFalse(assembly.healthy());}
            var value=recovered(path,1L<<20).pending().values().iterator().next().text().value();
            assertTrue(value.equals("START")||value.equals("START\ntail"));
            if(boundary.equals("append-header")||boundary.equals("append-payload"))assertEquals("START",value);
            try(var assembly=assembler(path,1L<<20,point->{})){assertEquals(1,assembly.pendingCount());}
        }
    }
    @Test void compactionPublicationFaultsRecoverAuthoritativeGenerationWithinPhysicalBound()throws Exception{
        for(String boundary:List.of("snapshot-write","snapshot-sync","snapshot-durable","journal-write","journal-sync","journal-durable",
                "generation-directory","pointer-write","pointer-sync","pointer-durable","pointer-move","pointer-directory","publication-durable","cleanup","cleanup-directory")){
            Path path=directory.resolve(boundary);var armed=new AtomicReference<String>();long quota=32768;
            var peak=new java.util.concurrent.atomic.AtomicLong();
            try(var assembly=assembler(path,quota,point->{})){
                accept(assembly,"a",0,"START queued\nSTART a",Limits.defaults());accept(assembly,"b",0,"START b",Limits.defaults());
            }
            S2SStreamAssembler.State expected=recovered(path,quota);
            try(var store=new S2SAssemblyStore(path,quota,point->{peak.accumulateAndGet(physical(path),Math::max);if(point.equals(armed.get()))throw new IOException("injected "+point);})){
                store.recover();store.initialize(expected);armed.set(boundary);
                boolean failed=false;
                for(int i=1;i<1000&&!failed;i++){
                    var receipts=new LinkedHashMap<>(expected.receipts());receipts.put(String.format("%064x",i),"b".repeat(64));if(receipts.size()>20)receipts.remove(receipts.keySet().iterator().next());
                    var next=new S2SStreamAssembler.State(expected.configuration(),expected.pending(),expected.outbox(),receipts,false);
                    try{store.commit(next);expected=next;}catch(IOException injected){failed=true;}
                }
                assertTrue(failed,"boundary must be reached: "+boundary);
            }
            var actual=recovered(path,quota);assertArrayEquals(HecProtocol.JSON.writeValueAsBytes(expected),HecProtocol.JSON.writeValueAsBytes(actual),boundary);
            assertEquals(new ArrayList<>(expected.pending().keySet()),new ArrayList<>(actual.pending().keySet()),boundary);
            assertEquals(new ArrayList<>(expected.receipts().keySet()),new ArrayList<>(actual.receipts().keySet()),boundary);
            Path reference=directory.resolve("reference-"+boundary);Files.createDirectories(reference);Files.write(reference.resolve("state"),wrap(HecProtocol.JSON.writeValueAsBytes(expected)));
            assertEquals(deliver(reference,quota),deliver(path,quota),"complete delivered payload/metadata/order: "+boundary);
            assertTrue(peak.get()<=8*quota+32768,"transient generation files: "+boundary);
        }
    }
    static long physical(Path path)throws IOException{try(var files=Files.list(path)){long total=0;for(Path file:files.toList())total+=Files.size(file);return total;}}
    @Test void freshPublicationCrashBoundariesRefuseLegacyReaderAndRetainAcceptedState()throws Exception{
        for(String boundary:List.of("fresh-marker-write","fresh-marker-sync","fresh-marker-durable","fresh-marker-move","fresh-marker-directory",
                "snapshot-write","snapshot-sync","snapshot-durable","journal-write","journal-sync","journal-durable","generation-directory",
                "pointer-write","pointer-sync","pointer-durable","pointer-move","pointer-directory","publication-durable","cleanup","cleanup-directory",
                "established-write","established-sync","established-durable","established-directory","append-header","append-payload","append-sync","append-durable")){
            Path path=directory.resolve("fresh-"+boundary);
            if(boundary.equals("cleanup")){Files.createDirectories(path);Files.writeString(path.resolve("pointer-next-v3"),"unpublished");}
            try(var assembly=assembler(path,1L<<20,point->{if(point.equals(boundary))throw new IOException("injected");})){
                assertThrows(IOException.class,()->accept(assembly,0,"START"));
            }
            try(var assembly=assembler(path,1L<<20,point->{})){
                if(assembly.pendingCount()==0)accept(assembly,0,"START");
            }
            // Execute the released 0.2.0 recover method in an isolated classloader.
            assertOldReaderRefuses(path);
            byte[] before=HecProtocol.JSON.writeValueAsBytes(recovered(path,1L<<20));
            try(var assembly=assembler(path,1L<<20,point->{})){assertEquals(1,assembly.pendingCount());}
            assertArrayEquals(before,HecProtocol.JSON.writeValueAsBytes(recovered(path,1L<<20)));
        }
    }
    void assertOldReaderRefuses(Path path)throws Exception{
        assertTrue(Files.isRegularFile(Path.of("logstash-input-splunk_hec-0.2.0-java.gem")),"Prepare baseline explicitly: python3 scripts/prepare-v2-baseline.py --download (see docs/installation.md)");
        Path jar=directory.resolve("released-v2.jar");
        if(!Files.exists(jar)){
            // Read gem's nested tar archives without using the active plugin classes.
            Process process=new ProcessBuilder("python3","-c","import tarfile,sys; g=tarfile.open(sys.argv[1]); d=tarfile.open(fileobj=g.extractfile('data.tar.gz'),mode='r:gz'); j=[m for m in d.getmembers() if m.name.endswith('.jar')][0]; open(sys.argv[2],'wb').write(d.extractfile(j).read())",
                "logstash-input-splunk_hec-0.2.0-java.gem",jar.toString()).inheritIO().start();assertEquals(0,process.waitFor());
        }
        try(var loader=new java.net.URLClassLoader(new java.net.URL[]{jar.toUri().toURL()},ClassLoader.getPlatformClassLoader())){
            var type=loader.loadClass("org.logstashplugins.hec.S2SAssemblyStore");var constructor=type.getDeclaredConstructor(Path.class,long.class);constructor.setAccessible(true);
            Object old=constructor.newInstance(path,1L<<20);var recover=type.getDeclaredMethod("recover");recover.setAccessible(true);var close=type.getDeclaredMethod("close");close.setAccessible(true);
            try{var error=assertThrows(java.lang.reflect.InvocationTargetException.class,()->recover.invoke(old));assertInstanceOf(IOException.class,error.getCause());}
            finally{close.invoke(old);}
        }
    }
    @Test void recoveredPointerDirectoryIsSyncedBeforeCleanup()throws Exception{
        Path path=directory.resolve("sync-order");try(var assembly=assembler(path,1L<<20,point->{})){accept(assembly,0,"START");}
        Files.writeString(path.resolve("snapshot-v3-99"),"old generation");
        assertThrows(IOException.class,()->assembler(path,1L<<20,point->{if(point.equals("recovered-pointer-directory"))throw new IOException("sync failed");}));
        assertTrue(Files.exists(path.resolve("snapshot-v3-99")),"failed resync must not clean referenced predecessors");
    }
    @Test void missingPublishedPointerNeverResetsFreshOrMigratedWork()throws Exception{
        for(boolean migrate:List.of(false,true)){
            Path path=directory.resolve("missing-"+migrate);try(var assembly=assembler(path,1L<<20,point->{})){accept(assembly,0,"START");}
            if(migrate){var original=recovered(path,1L<<20);Path migrated=directory.resolve("migrated");Files.createDirectories(migrated);Files.write(migrated.resolve("state"),wrap(HecProtocol.JSON.writeValueAsBytes(original)));path=migrated;
                try(var assembly=assembler(path,1L<<20,point->{})){accept(assembly,5,"accepted after migration");}}
            Files.delete(path.resolve("current-v3"));Path target=path;byte[] journal=Files.readAllBytes(path.resolve("journal-v3-1"));
            assertThrows(IOException.class,()->assembler(target,1L<<20,point->{}));assertArrayEquals(journal,Files.readAllBytes(path.resolve("journal-v3-1")));
        }
    }
    @Test void oversizedPreservedBackupFailsBeforeHealthyRecovery()throws Exception{
        Path source=directory.resolve("backup-source");try(var assembly=assembler(source,1L<<20,point->{})){accept(assembly,0,"START "+"x".repeat(100000));}
        var state=recovered(source,1L<<20);Path target=directory.resolve("backup-tight");Files.createDirectories(target);Files.write(target.resolve("state"),wrap(HecProtocol.JSON.writeValueAsBytes(state)));
        try(var assembly=assembler(target,1L<<20,point->{})){var queue=new java.util.concurrent.LinkedBlockingQueue<Map<String,Object>>();assembly.start(queue::add);accept(assembly,100006,"START next");assertNotNull(queue.poll(3,java.util.concurrent.TimeUnit.SECONDS));}
        assertThrows(IOException.class,()->assembler(target,4096,point->{}));assertTrue(Files.exists(target.resolve("backup-v2")));
    }
    @Test void malformedTaggedEnvelopesAreRejected()throws Exception{
        for(String json:List.of("null","{}","{\"map\":[],\"list\":[]}","{\"map\":{}}","{\"map\":[[\"x\",1]]}","{\"map\":[[\"x\",null,0]]}",
                "{\"map\":[[1,null]]}","{\"map\":[[\"x\",null],[\"x\",null]]}","{\"list\":null}","{\"number\":[\"Long\",\"1\",\"extra\"]}",
                "{\"number\":[\"Double\",\"NaN\"]}","{\"timestamp\":0}","{\"timestamp\":\"invalid\"}")){
            Object value=HecProtocol.JSON.readValue(json,Object.class);assertThrows(RuntimeException.class,()->S2SAssemblyStore.envelope(value),json);
        }
        var value=Map.of("map",List.of(List.of("x",Map.of("list",List.of(Map.of("number",List.of("Double","-0.0")))))));
        assertNotNull(S2SAssemblyStore.envelope(value));
    }
    @Test void oversizedStateRefusalComparisonIsBoundedAndNonmutating()throws Exception{
        Path path=directory.resolve("oversized-marker");Files.createDirectories(path);Path state=path.resolve("state");
        try(var file=java.nio.channels.FileChannel.open(state,StandardOpenOption.CREATE,StandardOpenOption.WRITE)){file.position(S2SAssemblyStore.SAFETY_MAXIMUM+100);file.write(ByteBuffer.wrap(new byte[]{1}));}
        long length=Files.size(state);assertThrows(IOException.class,()->assembler(path,4096,point->{}));assertEquals(length,Files.size(state));
    }
    @Test void authenticatedReceiptOverwriteFailsWithUnchangedJournal()throws Exception{
        Path path=directory.resolve("overwrite");try(var assembly=assembler(path,1L<<20,point->{})){accept(assembly,0,"START");}
        var state=recovered(path,1L<<20);String key=state.receipts().keySet().iterator().next();
        var tx=new S2SAssemblyStore.Transaction(state.configuration(),List.of(),List.of(),List.of(),List.of(),List.of(),Map.of(key,"a".repeat(64)),null,null,false);
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(tx);ByteBuffer header=ByteBuffer.allocate(88).putInt(0x53325333).putInt(3).putLong(2).putLong(payload.length);
        header.put(java.util.HexFormat.of().parseHex(TokenStore.fingerprint(Arrays.copyOf(header.array(),24)))).put(java.util.HexFormat.of().parseHex(TokenStore.fingerprint(payload)));
        Path journal=S2SAssemblyTest.journal(path);Files.write(journal,header.array(),StandardOpenOption.APPEND);Files.write(journal,payload,StandardOpenOption.APPEND);byte[] before=Files.readAllBytes(journal);
        assertThrows(IOException.class,()->assembler(path,1L<<20,point->{}));assertArrayEquals(before,Files.readAllBytes(journal));
    }
    @Test void fullCompletionByteLimitRejectsEscapingGrowthAndRetainsCompletablePrefix()throws Exception{
        Path path=directory.resolve("escaped-limit");var limits=new Limits(16,64,10<<20,64<<20,128L<<20,4096,10000,100,30000,1000,10000);
        S2SStreamAssembler.State accepted=null;String expected=null;long offset=5;
        try(var assembly=assembler(path,1L<<20,point->{})){
            accept(assembly,"source",0,"START",limits);expected="START";
            String suffix="\"\\é".repeat(80);
            boolean rejected=false;
            for(int i=0;i<10;i++){
                var token=new TokenStore(null,ProtocolTest.INLINE,s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);
                var event=new S2SDecoder.Event("host","source","test","channel","main",10,7,offset,1,1700000000,"1700000000.123456789",
                    List.of(),null,List.of(),Map.of("zero",-0.0,"large",new java.math.BigInteger("18446744073709551615")),Map.of(),suffix.getBytes(StandardCharsets.UTF_8));
                try(var lease=memory.lease()){assertEquals(1,new S2SEvents(limits,new HecProtocol(limits)).mapWithIdentity(List.of(event),token,Map.of(),"standalone",lease).size(),"each suffix must pass legacy mapping");}
                assertTrue(expected.length()+1+suffix.length()<limits.event(),"character guard must not reject the tested suffix");
                accepted=(S2SStreamAssembler.State)HttpTlsTest.privateField(assembly,"state");
                try{accept(assembly,"source",offset,suffix,limits);expected+="\n"+suffix;offset+=event.raw().length;}
                catch(HecException error){rejected=true;break;}
            }
            assertTrue(rejected,"cached completed-byte validation must reject accumulated FULL size");
            assertTrue(accepted.pending().values().iterator().next().contributions().size()>1,"a fitting accumulated prefix must have been accepted");
            var retained=recoveredCopy(path,1L<<20);assertEquals(expected,retained.pending().values().iterator().next().text().value());
        }
        try(var assembly=assembler(path,1L<<20,point->{})){assertEquals(1,assembly.pendingCount());}
        Path completion=directory.resolve("completion");Files.createDirectories(completion);Files.write(completion.resolve("state"),wrap(HecProtocol.JSON.writeValueAsBytes(accepted)));
        assertEquals(expected,deliver(completion,1L<<20).getFirst().get("event"));
    }
    public static void main(String[] args)throws Exception{
        if(args[0].equals("sleep")){Thread.sleep(60000);return;}
        Path path=Path.of(args[0]);String boundary=args[1];var armed=new java.util.concurrent.atomic.AtomicBoolean();
        try(var store=new S2SAssemblyStore(path,8192,point->{if(armed.get()&&point.equals(boundary))Runtime.getRuntime().halt(73);})){var state=S2SStreamAssembler.recoveryMapper(1L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);
            store.initialize(state);armed.set(true);for(int i=0;i<10000;i++)store.commit(state);}
        throw new IllegalStateException("halt boundary not reached");
    }
    @Test void subprocessHaltPublicationReopensExactAcknowledgedState()throws Exception{
        Path seed=directory.resolve("halt-seed");try(var assembly=assembler(seed,8192,point->{})){accept(assembly,0,"START first\nSTART pending");}
        var expected=recovered(seed,8192);
        String classpath=String.join(java.io.File.pathSeparator,List.of(
            S2SJournalTest.class.getProtectionDomain().getCodeSource().getLocation().getPath(),
            S2SAssemblyStore.class.getProtectionDomain().getCodeSource().getLocation().getPath(),
            "vendor/jars/*",".cache/logstash-jars/*"));
        for(String boundary:List.of("snapshot-write","snapshot-sync","journal-write","journal-sync","generation-directory","pointer-write","pointer-sync","pointer-move","pointer-directory","publication-durable","cleanup")){
            Path path=directory.resolve("halt-"+boundary);copy(seed,path);
            Process process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",classpath,S2SJournalTest.class.getName(),path.toString(),boundary).redirectErrorStream(true).redirectOutput(path.resolve("process.log").toFile()).start();
            try{
                assertTrue(process.waitFor(20,java.util.concurrent.TimeUnit.SECONDS),"finite process-crash deadline");assertEquals(73,process.exitValue(),Files.readString(path.resolve("process.log")));
            }finally{cleanupChild(process);}
            var actual=recovered(path,8192);assertArrayEquals(HecProtocol.JSON.writeValueAsBytes(expected),HecProtocol.JSON.writeValueAsBytes(actual),boundary);
            try(var assembly=assembler(path,8192,point->{})){assertEquals(1,assembly.pendingCount());assertEquals(1,assembly.outputCount());}
        }
    }
    private static void cleanupChild(Process process)throws InterruptedException{
        if(process.isAlive())process.destroy();
        if(!process.waitFor(2,java.util.concurrent.TimeUnit.SECONDS)){process.destroyForcibly();assertTrue(process.waitFor(5,java.util.concurrent.TimeUnit.SECONDS),"halt child cleanup deadline");}
    }
    @Test void timedOutHaltChildIsDestroyedAndAwaited()throws Exception{
        Process process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",
            S2SJournalTest.class.getProtectionDomain().getCodeSource().getLocation().getPath()+java.io.File.pathSeparator+"vendor/jars/*"+java.io.File.pathSeparator+"build/classes/java/main"+java.io.File.pathSeparator+".cache/logstash-jars/*",
            S2SJournalTest.class.getName(),"sleep").redirectOutput(directory.resolve("timeout-child.log").toFile()).redirectErrorStream(true).start();
        try{assertFalse(process.waitFor(100,java.util.concurrent.TimeUnit.MILLISECONDS));}finally{cleanupChild(process);}
        assertFalse(process.isAlive());
    }
    @Test void existingEstablishedMarkerIsForcedBeforeRecoveryAcceptance()throws Exception{
        Path path=directory.resolve("established-resync");
        try(var assembly=assembler(path,1L<<20,point->{if(point.equals("established-sync"))throw new IOException("interrupted force");})){
            assertThrows(IOException.class,()->accept(assembly,0,"START"));
        }
        assertArrayEquals(new byte[]{3},Files.readAllBytes(path.resolve("established-v3")));
        var boundaries=new ArrayList<String>();
        try(var assembly=assembler(path,1L<<20,boundaries::add)){accept(assembly,0,"START");}
        assertTrue(boundaries.indexOf("established-recovery-sync")>=0);
        assertTrue(boundaries.indexOf("established-recovery-sync")<boundaries.indexOf("established-directory"));
        try(var assembly=assembler(path,1L<<20,point->{})){assertEquals(1,assembly.pendingCount());}
    }
    @Test void invalidPublishedPointerNeverFallsBackToOldSnapshotOrBackup()throws Exception{
        Path path=directory.resolve("pointer");try(var assembly=assembler(path,1L<<20,point->{})){accept(assembly,0,"START");}
        byte[] pointer=Files.readAllBytes(path.resolve("current-v3"));pointer[pointer.length-1]^=1;Files.write(path.resolve("current-v3"),pointer);
        assertThrows(IOException.class,()->assembler(path,1L<<20,point->{}));
    }
    @Test void migrationInterruptionsPreserveOriginalAndOldReaderRefusal()throws Exception{
        Path source=directory.resolve("source");long quota=1L<<20;
        try(var assembly=assembler(source,quota,point->{})){accept(assembly,0,"START first\nSTART pending");}
        var old=recovered(source,quota);byte[] payload=HecProtocol.JSON.writeValueAsBytes(old),original=wrap(payload);
        for(String boundary:List.of("migration-backup-write","migration-backup-sync","migration-backup-durable","migration-backup-move","migration-backup-directory","migration-marker-write","migration-marker-sync","migration-marker-durable",
                "migration-marker-move","migration-marker-directory","snapshot-write","snapshot-sync","journal-write","journal-sync","generation-directory","pointer-write","pointer-sync","pointer-move","pointer-directory","publication-durable","cleanup-directory")){
            Path path=directory.resolve(boundary);Files.createDirectories(path);Files.write(path.resolve("state"),original);
            assertThrows(IOException.class,()->assembler(path,quota,point->{if(point.equals(boundary))throw new IOException("injected "+point);}));
            try(var assembly=assembler(path,quota,point->{})){assertEquals(1,assembly.pendingCount());assertEquals(1,assembly.outputCount());}
            assertArrayEquals(original,Files.readAllBytes(path.resolve("backup-v2")));assertTrue(Files.size(path.resolve("state"))<65,"0.2.0 checksum parser must refuse marker");
            var migrated=recovered(path,quota);assertArrayEquals(payload,HecProtocol.JSON.writeValueAsBytes(migrated));
        }
    }
    @Test void invalidLegacyStateAndTightenedQuotaDoNotPublishMigrationMarker()throws Exception{
        Path source=directory.resolve("source");try(var assembly=assembler(source,1L<<20,point->{})){accept(assembly,0,"START first\n"+"trace\n".repeat(40));}
        var old=recovered(source,1L<<20);byte[] original=wrap(HecProtocol.JSON.writeValueAsBytes(old));
        Path tight=directory.resolve("tight");Files.createDirectories(tight);Files.write(tight.resolve("state"),original);
        assertThrows(IOException.class,()->assembler(tight,original.length-65,point->{}));assertArrayEquals(original,Files.readAllBytes(tight.resolve("state")));assertFalse(Files.exists(tight.resolve("backup-v2")));
        original[original.length-1]^=1;Files.write(tight.resolve("state"),original);
        assertThrows(IOException.class,()->assembler(tight,1L<<20,point->{}));assertArrayEquals(original,Files.readAllBytes(tight.resolve("state")));
    }
    @Test void authenticatedInvalidOperationsAndSequencesFailClosed()throws Exception{
        Path source=directory.resolve("source");long quota=1L<<20;try(var assembly=assembler(source,quota,point->{})){accept(assembly,0,"START");}
        byte[] prefix=S2SAssemblyTest.durableBytes(source);var state=recovered(source,quota);
        var invalid=new S2SAssemblyStore.Transaction(state.configuration(),List.of("missing"),List.of(),List.of(),List.of(),List.of(),Map.of(),null,null,false);
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(invalid);ByteBuffer header=ByteBuffer.allocate(88).putInt(0x53325333).putInt(3).putLong(2).putLong(payload.length);
        header.put(java.util.HexFormat.of().parseHex(TokenStore.fingerprint(Arrays.copyOf(header.array(),24))));header.put(java.util.HexFormat.of().parseHex(TokenStore.fingerprint(payload)));
        Files.write(S2SAssemblyTest.journal(source),header.array(),StandardOpenOption.APPEND);Files.write(S2SAssemblyTest.journal(source),payload,StandardOpenOption.APPEND);
        assertThrows(IOException.class,()->assembler(source,quota,point->{}));assertEquals(prefix.length+88+payload.length,Files.size(S2SAssemblyTest.journal(source)));
    }
    static byte[] wrap(byte[] payload){byte[] prefix=(TokenStore.fingerprint(payload)+"\n").getBytes(StandardCharsets.US_ASCII);byte[] result=Arrays.copyOf(prefix,prefix.length+payload.length);System.arraycopy(payload,0,result,prefix.length,payload.length);return result;}
    static void copy(Path source,Path target)throws Exception{Files.createDirectories(target);try(var files=Files.list(source)){for(Path file:files.toList())Files.copy(file,target.resolve(file.getFileName()));}}
}
