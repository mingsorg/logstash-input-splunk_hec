package org.logstashplugins.hec;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Runs against the jar extracted from the explicitly selected gem, including 0.2.0. */
public final class JournalProbe {
    static final String RULES="[{\"match\":\"exact\",\"sourcetype\":\"test\",\"event_start_pattern\":\"^START\",\"flush_timeout_ms\":60000}]";
    static final MemoryBudget MEMORY=new MemoryBudget(2L<<30);
    static final AtomicLong CLOCK=new AtomicLong(1000);
    static final long QUOTA=32L<<20;
    static final Limits LIMITS=new Limits(16,64,32<<20,64<<20,128L<<20,32<<20,10000,100,30000,1000,10000);
    static TokenStore.Token token()throws Exception{return new TokenStore(null,"[{\"token\":\"11111111-1111-4111-8111-111111111111\",\"useACK\":true}]",s->{}).authenticate("Splunk 11111111-1111-4111-8111-111111111111",null);}
    static S2SStreamAssembler open(Path path)throws Exception{return new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",QUOTA,10,MEMORY,System.err::println,CLOCK::get);}
    static S2SStreamAssembler small(Path path)throws Exception{return new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",8192,10,MEMORY,System.err::println,CLOCK::get);}
    static long physical(Path path)throws java.io.IOException{try(var files=Files.list(path)){long total=0;for(Path file:files.toList())total+=Files.size(file);return total;}}
    static void accept(S2SStreamAssembler assembly,String source,long offset,String text)throws Exception{
        var fields=new LinkedHashMap<String,Object>();fields.put("large",new java.math.BigInteger("18446744073709551615"));fields.put("decimal",new java.math.BigDecimal("1.234567890123456789"));fields.put("zero",-0.0);
        var event=new S2SDecoder.Event("host",source,"test","channel","main",10,7,offset,1,1700000000,"1700000000.123456789",List.of(),null,List.of(),fields,Map.of(),text.getBytes(StandardCharsets.UTF_8));
        try(var lease=MEMORY.lease()){assembly.accept(List.of(event),token(),Map.of(),"batch-"+source+offset,"http",LIMITS,lease,null);}
    }
    static void drain(S2SStreamAssembler assembly,Path output)throws Exception{
        CLOCK.addAndGet(60001);try(var lease=MEMORY.lease()){assembly.expire(lease);}
        var received=new LinkedBlockingQueue<Map<String,Object>>();assembly.start(received::add);
        var events=new ArrayList<Map<String,Object>>();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);
        while(events.size()<2&&System.nanoTime()<deadline){var event=received.poll(1,TimeUnit.SECONDS);if(event!=null)events.add(event);}
        if(events.size()!=2)throw new IllegalStateException("missing migrated output");
        if(!events.get(0).get("event").equals("START queued\n")||!events.get(1).get("event").equals("START pending\ntrace"))throw new IllegalStateException("output order/content mismatch");
        Files.write(output,HecProtocol.JSON.writeValueAsBytes(events));
        deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);while(assembly.outputCount()!=0&&System.nanoTime()<deadline)Thread.sleep(10);
        if(assembly.outputCount()!=0)throw new IllegalStateException("outbox handoff did not commit");
        accept(assembly,"source",0,"START queued\nSTART pending");accept(assembly,"source",26,"trace");
        if(assembly.pendingCount()!=0||assembly.outputCount()!=0)throw new IllegalStateException("migration retry was not suppressed");
    }
    static long journalSize(Path path)throws Exception{try(var files=Files.list(path)){return files.filter(file->file.getFileName().toString().startsWith("journal-v3-")).mapToLong(file->{try{return Files.size(file);}catch(Exception e){throw new RuntimeException(e);}}).sum();}}
    public static void main(String[] arguments)throws Exception{
        String action=arguments[0];Path path=Path.of(arguments[1]);
        if(action.equals("seed")){
            try(var assembly=open(path)){accept(assembly,"source",0,"START queued\nSTART pending");if(assembly.pendingCount()!=1||assembly.outputCount()!=1)throw new IllegalStateException("seed needs pending/outbox");}return;
        }
        if(action.equals("continue")){
            try(var assembly=open(path)){if(assembly.pendingCount()!=1||assembly.outputCount()!=1)throw new IllegalStateException("retained migration state missing");accept(assembly,"source",26,"trace");drain(assembly,Path.of(arguments[2]));}return;
        }
        if(action.equals("refuse")){
            try(var assembly=open(path)){throw new IllegalStateException("old reader opened migrated state");}catch(java.io.IOException expected){System.out.println("OLD_READER_REFUSED");}return;
        }
        if(action.equals("receipts")){
            var values=new LinkedHashMap<String,String>();for(int i=0;i<4096;i++)values.put(String.format("%064x",i),"a".repeat(64));
            var visits=new AtomicLong();Map<String,String> tracked=new AbstractMap<>(){
                @Override public Set<Entry<String,String>> entrySet(){visits.incrementAndGet();return values.entrySet();}
                @Override public int size(){return values.size();}
            };
            long elapsed;
            try(var assembly=open(path)){
                var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);var original=(S2SStreamAssembler.State)field.get(assembly);
                field.set(assembly,new S2SStreamAssembler.State(original.configuration(),Map.of(),List.of(),tracked,false));
                long exact=assembly.liveBytes();visits.set(0);long start=System.nanoTime();
                for(int i=0;i<1000;i++)if(assembly.accountedLiveBytes()!=exact)throw new IllegalStateException("receipt accounting mismatch");
                elapsed=System.nanoTime()-start;if(visits.get()!=0)throw new IllegalStateException("capacity traversed saturated receipts");
            }
            System.out.println(HecProtocol.JSON.writeValueAsString(Map.of("receipts",4096,"checks",1000,"capacity_ns",elapsed,"receipt_map_traversals",visits.get(),"memory_released",MEMORY.used()==0)));return;
        }
        if(action.equals("scale")){
            int lines=Integer.parseInt(arguments[2]);if(lines<2||lines>9997)throw new IllegalArgumentException("scale lines must be 2..9997 (reserve real producer and continuation slots)");
            final int producerCap=Math.min(32,LIMITS.events()-lines-1);
            int producerContributions=0,retainedContributions=0;
            var latencies=new ArrayList<Long>();long total=0,max=0,compactionNanos=0,compactions=0,heapPeak=0,reserved=0,finalizationNanos=0,replayNanos=0,progressNanos=0;
            try(var assembly=open(path)){
                accept(assembly,"source",0,"START");long offset=5;
                for(int i=1;i<lines;i++){
                    long before=journalSize(path),start=System.nanoTime();accept(assembly,"source",offset,"x".repeat(128));long elapsed=System.nanoTime()-start;
                    long after=journalSize(path);latencies.add(elapsed);long delta=after-before;
                    if(delta<0){compactions++;compactionNanos+=elapsed;delta=after;}
                    total+=delta;max=Math.max(max,delta);offset+=128;
                    heapPeak=Math.max(heapPeak,Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory());reserved=MEMORY.used();
                    if(delta>8192)throw new IllegalStateException("append copied accumulated prefix");
                }
                // Keep the long-state sender actively appending while another sender requests admission.
                var started=new CountDownLatch(1);var progressStarted=new CountDownLatch(1);var stop=new java.util.concurrent.atomic.AtomicBoolean();var producerError=new java.util.concurrent.atomic.AtomicReference<Throwable>();
                final long nextOffset=offset;
                Thread producer=Thread.ofVirtual().start(()->{
                    try{
                        long cursor=nextOffset;
                        for(int i=0;i<producerCap&&(i<2||!stop.get());i++){
                            String text="growth-"+i;accept(assembly,"source",cursor,text);cursor+=text.getBytes(StandardCharsets.UTF_8).length;
                            if(i==0){started.countDown();if(!progressStarted.await(5,TimeUnit.SECONDS))throw new IllegalStateException("progress request not started");}
                        }
                    }catch(Throwable error){producerError.set(error);started.countDown();}
                });
                var token=token();var direct=new S2SDecoder.Event("other","other","unmatched","other","main",0x4a,8,0,1,1700000000,null,List.of(),null,List.of(),Map.of(),Map.of(),"progress".getBytes(StandardCharsets.UTF_8));
                long progressStart=System.nanoTime();var progress=new CompletableFuture<Boolean>();
                try{
                    if(!started.await(5,TimeUnit.SECONDS))throw new IllegalStateException("concurrent producer not started");
                    if(producerError.get()!=null)throw new IllegalStateException("initial real append failed",producerError.get());
                    progressStart=System.nanoTime();
                    Thread.ofVirtual().start(()->{try(var lease=MEMORY.lease()){progressStarted.countDown();progress.complete(assembly.accept(List.of(direct),token,Map.of(),"other","other",Limits.defaults(),lease,null).size()==1);}catch(Throwable error){progress.completeExceptionally(error);}});
                    if(!progress.get(5,TimeUnit.SECONDS))throw new IllegalStateException("unrelated sender blocked");progressNanos=System.nanoTime()-progressStart;
                }finally{stop.set(true);progressStarted.countDown();producer.join(5000);}
                if(producer.isAlive()||producerError.get()!=null)throw new IllegalStateException("concurrent producer failed",producerError.get());
                var stateField=S2SStreamAssembler.class.getDeclaredField("state");stateField.setAccessible(true);
                var retained=(S2SStreamAssembler.State)stateField.get(assembly);
                retainedContributions=retained.pending().values().iterator().next().contributions().size();
                producerContributions=retainedContributions-lines;
                if(producerContributions<2||producerContributions>producerCap||retainedContributions>=LIMITS.events())throw new IllegalStateException("producer must grow retained state by multiple capped contributions");
            }
            Path pendingCopy=path.resolveSibling(path.getFileName()+"-pending");copySpool(path,pendingCopy);
            long replayStart=System.nanoTime();
            try(var assembly=open(path)){
                replayNanos=System.nanoTime()-replayStart;if(assembly.pendingCount()!=1)throw new IllegalStateException("long replay missing");
                CLOCK.addAndGet(60001);long finalizationStart=System.nanoTime();try(var lease=MEMORY.lease()){assembly.expire(lease);}finalizationNanos=System.nanoTime()-finalizationStart;
                if(assembly.outputCount()!=1)throw new IllegalStateException("long event finalization missing");
            }
            Collections.sort(latencies);long physical;try(var files=Files.list(path)){physical=files.mapToLong(file->{try{return Files.size(file);}catch(Exception e){throw new RuntimeException(e);}}).sum();}
            var report=new LinkedHashMap<String,Object>();report.put("lines",lines);report.put("append_bytes",total);report.put("max_transaction_bytes",max);
            report.put("p50_ns",latencies.get(latencies.size()/2));report.put("p99_ns",latencies.get(latencies.size()*99/100));report.put("compactions",compactions);report.put("compaction_ns",compactionNanos);
            report.put("finalization_ns",finalizationNanos);report.put("physical_bytes",physical);report.put("heap_peak_observed_bytes",heapPeak);report.put("memory_reserved_bytes",reserved);report.put("memory_released",MEMORY.used()==0);report.put("unrelated_sender_progress",true);
            report.put("replay_ns",replayNanos);report.put("concurrent_unrelated_sender_ns",progressNanos);report.put("progress_bound_ns",TimeUnit.SECONDS.toNanos(5));
            report.put("producer_contribution_cap",producerCap);report.put("producer_actual_contributions",producerContributions);report.put("retained_contributions_after_progress",retainedContributions);report.put("contribution_limit",LIMITS.events());
            System.out.println(HecProtocol.JSON.writeValueAsString(report));return;
        }
        if(action.equals("halt-publication")){
            String boundary=arguments[2];var armed=new java.util.concurrent.atomic.AtomicBoolean();
            try(var store=new S2SAssemblyStore(path,8192,point->{if(armed.get()&&point.equals(boundary))Runtime.getRuntime().halt(73);})){byte[] bytes=store.recover();
                if(bytes==null)throw new IllegalStateException("halt probe requires acknowledged seed");
                var state=S2SStreamAssembler.recoveryMapper(32L<<20).readValue(bytes,S2SStreamAssembler.State.class);store.initialize(state);armed.set(true);
                // Force a publication while retaining the exact same acknowledged logical state.
                for(int i=0;i<10000;i++)store.commit(state);
            }
            throw new IllegalStateException("publication boundary not reached");
        }
        if(action.equals("compact-long")){
            Path pendingPath=path.resolveSibling(path.getFileName()+"-pending");
            S2SStreamAssembler.State before;
            try(var store=new S2SAssemblyStore(pendingPath,QUOTA)){before=S2SStreamAssembler.recoveryMapper(QUOTA).readValue(store.recover(),S2SStreamAssembler.State.class);}
            if(before.pending().size()!=1||before.pending().values().iterator().next().contributions().size()<500)throw new IllegalStateException("long pending chain required");
            Path reference=pendingPath.resolveSibling(pendingPath.getFileName()+"-reference");copySpool(pendingPath,reference);
            long start=System.nanoTime();
            try(var store=new S2SAssemblyStore(pendingPath,8L<<20)){
                var state=S2SStreamAssembler.recoveryMapper(32L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);store.initialize(state);
                store.compact();
            }
            long compact=System.nanoTime()-start;start=System.nanoTime();
            try(var store=new S2SAssemblyStore(pendingPath,8L<<20)){
                byte[] recovered=store.recover();
                if(!Arrays.equals(HecProtocol.JSON.writeValueAsBytes(before),recovered))throw new IllegalStateException("compacted pending state/order/receipts mismatch");
            }
            long restart=System.nanoTime()-start;
            var expected=continueLong(reference);var actual=continueLong(pendingPath);
            if(!Arrays.equals(HecProtocol.JSON.writeValueAsBytes(expected),HecProtocol.JSON.writeValueAsBytes(actual)))throw new IllegalStateException("long completion envelope/ID mismatch");
            System.out.println(HecProtocol.JSON.writeValueAsString(Map.of("long_compaction_ns",compact,"compacted_restart_ns",restart,"physical_bytes",physical(pendingPath),"complete_equivalence",true,"pending_contributions",before.pending().values().iterator().next().contributions().size())));return;
        }
        if(action.equals("soak")){
            long count=0,compactions=0,compactionNanos=0;var peak=new AtomicLong();var publicationSamples=new AtomicLong();var received=new LinkedBlockingQueue<Map<String,Object>>();
            try(var assembly=new S2SStreamAssembler(path,S2SLineBreakerPolicy.parse(RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",8192,10,MEMORY,System.err::println,CLOCK::get,boundary->{
                peak.accumulateAndGet(physical(path),Math::max);
                if(boundary.equals("pointer-write")||boundary.equals("publication-durable"))publicationSamples.incrementAndGet();
            })){
                assembly.start(received::add);
                for(int i=0;i<2000;i++){
                    long before=journalSize(path),started=System.nanoTime();accept(assembly,"source",i*20L,"START "+i);CLOCK.addAndGet(60001);
                    try(var lease=MEMORY.lease()){assembly.expire(lease);}
                    var event=received.poll(30,TimeUnit.SECONDS);if(event==null||!event.get("event").equals("START "+i))throw new IllegalStateException("soak event mismatch");count++;
                    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);while(assembly.outputCount()!=0&&System.nanoTime()<deadline)Thread.sleep(1);
                    if(assembly.outputCount()!=0)throw new IllegalStateException("soak handoff did not commit");
                    if(journalSize(path)<before){compactions++;compactionNanos+=System.nanoTime()-started;}
                    peak.accumulateAndGet(physical(path),Math::max);
                }
            }
            if(compactions==0||publicationSamples.get()==0)throw new IllegalStateException("compaction publication coverage failed");
            System.out.println(HecProtocol.JSON.writeValueAsString(Map.of("events",count,"peak_physical_bytes",peak.get(),"quota",8192,"transient_publication_samples",publicationSamples.get(),"compactions",compactions,"compaction_observation_ns",compactionNanos,"memory_released",MEMORY.used()==0)));return;
        }
        throw new IllegalArgumentException("unknown probe action");
    }
    static void copySpool(Path source,Path target)throws Exception{
        Files.createDirectories(target);try(var files=Files.list(source)){for(Path file:files.toList())Files.copy(file,target.resolve(file.getFileName()));}
    }
    static Map<String,Object> continueLong(Path path)throws Exception{
        CLOCK.set(1000);var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=open(path)){
            S2SStreamAssembler.State state;
            var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);state=(S2SStreamAssembler.State)field.get(assembly);
            var pending=state.pending().values().iterator().next();accept(assembly,"source",pending.offset(),"continued");
            CLOCK.addAndGet(60001);try(var lease=MEMORY.lease()){assembly.expire(lease);}assembly.start(received::add);
            var output=received.poll(30,TimeUnit.SECONDS);if(output==null)throw new IllegalStateException("long completion missing");return output;
        }
    }
}
