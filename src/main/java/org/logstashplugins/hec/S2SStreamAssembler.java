package org.logstashplugins.hec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Transactional source-isolated assembly plus one owned, interruptible outbox worker. */
final class S2SStreamAssembler implements AutoCloseable {
    record Pending(Object envelope,String text,String delimiter,String rule,String chain,String attributes,String origin,List<Object> contributions,
                   long touched,long timeout,long offset,long sequence,int eventLimit,String sender) {}
    record Output(String id,Object envelope,String sender) {}
    /** Holds back later output of the listed senders (except the listed barrier outputs) until the caller has enqueued its direct events. */
    private static final class Gate{
        final Set<String> senders,ids;
        Gate(Set<String> senders,Set<String> ids){this.senders=Set.copyOf(senders);this.ids=new HashSet<>(ids);}
    }
    private record Direct(List<Map<String,Object>> events,Set<String> predecessors) {}
    /** Direct events plus the ordering gate that stays up until {@link #close()} after the caller has enqueued them. */
    final class Ordered implements AutoCloseable{
        private final List<Map<String,Object>> events;private final Gate gate;private final List<Direct> steps;
        private Ordered(List<Map<String,Object>> events,Gate gate,List<Direct> steps){this.events=events;this.gate=gate;this.steps=steps;}
        List<Map<String,Object>> events(){return events;}
        void enqueue(Consumer<Map<String,Object>> sink)throws InterruptedException{
            for(Direct step:steps){
                synchronized(S2SStreamAssembler.this){
                    if(gate!=null)gate.ids.addAll(step.predecessors);
                    S2SStreamAssembler.this.notifyAll();await(step.predecessors);
                }
                // Never hold the assembly monitor while a Logstash queue may apply backpressure.
                for(var event:step.events){if(stopped||blocked||Thread.currentThread().isInterrupted())throw HecException.busy();sink.accept(event);}
            }
        }
        @Override public void close(){release(gate);}
    }
    private final List<Gate> gates=new ArrayList<>();
    private record Mapped(List<Map<String,Object>> legacy,Map<String,Object> effective) {}
    record State(String configuration,Map<String,Pending> pending,List<Output> outbox,Map<String,String> receipts,boolean blocked) {}
    private final S2SLineBreakerPolicy policy;
    private final S2SAssemblyStore store;
    private final MemoryBudget.Lease reservation;
    private final MetadataMode mode;
    private final S2SMetadataFields metadataFields;
    private final int maxStreams;
    private final LongSupplier clock;
    private final Consumer<String> diagnostic;
    private State state;
    private Thread worker;
    private volatile boolean stopped,blocked;
    private volatile String failure;
    private final int receiptLimit;
    private static final class AssembledEventTooLarge extends RuntimeException {}

    S2SStreamAssembler(Path path,S2SLineBreakerPolicy policy,MetadataMode mode,S2SMetadataFields fields,
                       String metadataConfiguration,long maximum,int streams,MemoryBudget memory,Consumer<String> diagnostic)throws IOException{
        this(path,policy,mode,fields,metadataConfiguration,maximum,streams,memory,diagnostic,System::currentTimeMillis);
    }
    S2SStreamAssembler(Path path,S2SLineBreakerPolicy policy,MetadataMode mode,S2SMetadataFields fields,
                       String metadataConfiguration,long maximum,int streams,MemoryBudget memory,Consumer<String> diagnostic,LongSupplier clock)throws IOException{
        this.policy=policy;this.mode=mode;metadataFields=fields;maxStreams=streams;this.clock=clock;this.diagnostic=diagnostic;
        // Each SHA-256 key/value receipt occupies at most 134 JSON bytes including its comma.
        // Reserve at most a quarter of the snapshot for receipts, including the map's braces.
        receiptLimit=(int)Math.max(1,Math.min(4096,(maximum/4-2)/134));
        // Covers retained objects, staged copies, bounded JSON scratch and recovery simultaneously.
        reservation=memory.lease();reservation.charge(Math.multiplyExact(maximum,32));
        S2SAssemblyStore opened=null;
        try{
            opened=new S2SAssemblyStore(path,maximum);store=opened;
            String configuration=TokenStore.fingerprint("assembly-v2:"+policy.fingerprint+":"+mode+":"+metadataConfiguration);
            byte[] recovered=store.recover();
            state=recovered==null?new State(configuration,new LinkedHashMap<>(),new ArrayList<>(),new LinkedHashMap<>(),false):
                recoveryMapper(maximum).readValue(recovered,State.class);
            if(!configuration.equals(state.configuration))throw new IOException("assembly policy mismatch; restore configuration or explicitly migrate retained state");
            if(state.pending.size()>streams||state.receipts.size()>receiptLimit)throw new IOException("assembly recovery bounds exceeded");
            // Validate all tagged envelopes before opening listeners or emitting anything.
            for(var pending:state.pending.values())S2SAssemblyStore.envelope(pending.envelope);
            for(var output:state.outbox)S2SAssemblyStore.envelope(output.envelope);
            // Admission reserved finalization headroom under the quota in force at the time; recovery must prove the
            // same under the quota in force NOW, otherwise an ACKed tail could never be completed.
            try{validateFinalizationCapacity(state);}
            catch(IOException|AssembledEventTooLarge|HecException|ArithmeticException|ClassCastException|IllegalArgumentException|NullPointerException error){
                throw new IOException("assembly recovery bounds exceeded; retained state cannot be finalized under the configured s2s_assembly_max_bytes/s2s_assembly_max_streams",error);
            }
            blocked=state.blocked;if(blocked)diagnostic.accept("S2S assembly blocked; retained oversized stream requires explicit operator recovery");
        }catch(IOException|RuntimeException error){
            try{if(opened!=null)opened.close();}catch(IOException closeFailure){error.addSuppressed(closeFailure);}
            finally{reservation.close();}
            throw error;
        }
    }
    /** Recovery reads only snapshots the store already bounded to {@code maximum} bytes, so string/number limits follow that bound rather than Jackson's defaults. */
    private static com.fasterxml.jackson.databind.ObjectMapper recoveryMapper(long maximum){
        int bound=(int)Math.min(Integer.MAX_VALUE,Math.max(1,maximum+65));
        var factory=com.fasterxml.jackson.core.JsonFactory.builder().streamReadConstraints(com.fasterxml.jackson.core.StreamReadConstraints.builder()
            .maxStringLength(bound).maxNumberLength(bound).build()).build();
        return new com.fasterxml.jackson.databind.ObjectMapper(factory)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_LONG_FOR_INTS)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
    synchronized void start(Consumer<Map<String,Object>> sink){
        if(worker!=null||stopped)throw new IllegalStateException("assembly worker lifecycle");
        worker=Thread.ofVirtual().name("s2s-assembly").unstarted(()->run(sink));worker.start();
    }
    boolean healthy(){return !blocked&&!stopped;}
    String failure(){return failure;}

    /** Convenience form for callers that do not enqueue direct events themselves: the gate is released before returning. */
    List<Map<String,Object>> accept(List<S2SDecoder.Event> records,TokenStore.Token token,Map<String,String> request,
                String batch,String namespace,Limits limits,MemoryBudget.Lease memory,Map<String,Object> transport)throws IOException,InterruptedException{
        try(var ordered=acceptOrdered(records,token,request,batch,batch,namespace,limits,memory,transport)){return ordered.events();}
    }
    Ordered acceptOrdered(List<S2SDecoder.Event> records,TokenStore.Token token,Map<String,String> request,
                String batch,String namespace,Limits limits,MemoryBudget.Lease memory,Map<String,Object> transport)throws IOException,InterruptedException{
        return acceptOrdered(records,token,request,batch,batch,namespace,limits,memory,transport);
    }
    /**
     * Validates the entire decoded batch and stages mutations before one durable commit. Ordering is preserved per sender
     * (connection sender; host when the sender cannot be told apart). {@code legacyBatch} keeps non-selected IDs identical to the
     * non-assembly path; {@code batch} scopes selected positionless occurrences. The caller MUST close the result after enqueueing
     * its direct events.
     */
    synchronized Ordered acceptOrdered(List<S2SDecoder.Event> records,TokenStore.Token token,Map<String,String> request,
                String legacyBatch,String batch,String namespace,Limits limits,MemoryBudget.Lease memory,Map<String,Object> transport)throws IOException,InterruptedException{
        if(blocked||stopped)throw HecException.busy();
        Set<String> senders=new HashSet<>();
        for(var record:records){
            Map<String,Object> effective=new HashMap<>();
            effective.put("host",record.host()!=null?record.host():request.getOrDefault("host",token.defaults().get("host")));
            senders.add(senderOf(namespace,token,effective));
        }
        // A preceding caller may still be enqueueing direct records outside this monitor.
        // Serialize only overlapping senders; state is staged AFTER that caller releases its gate.
        while(gates.stream().anyMatch(gate->!Collections.disjoint(gate.senders,senders))){
            if(stopped||blocked)throw HecException.busy();wait(50);
        }
        if(stopped||blocked)throw HecException.busy();
        var pending=new LinkedHashMap<>(state.pending);var outbox=new ArrayList<>(state.outbox);var receipts=new LinkedHashMap<>(state.receipts);
        // Keys whose retained stream is still durable: an oversize block may only quarantine those.
        var committed=new HashSet<>(state.pending.keySet());
        List<Map<String,Object>> direct=new ArrayList<>();
        List<Direct> steps=new ArrayList<>();
        Set<String> barriers=new HashSet<>(),gated=new HashSet<>();
        HecProtocol protocol=new HecProtocol(limits);S2SEvents mapper=new S2SEvents(limits,protocol,mode,metadataFields);
        // Validate EVERY native envelope, UTF-8 payload and request count before even a
        // diagnosed oversize block can change previously accepted state. Keep the maps
        // for the staging pass so validation does not double-charge or reparse the batch.
        memory.charge(64L+64L*records.size());
        memory.charge(256L*records.size());
        var validatedReceipts=new HashMap<>(state.receipts);
        List<Mapped> mapped=new ArrayList<>();long validatedLines=0;int ordinal=0;
        for(var record:records){
            var legacy=mapper.mapWithIdentity(List.of(record),token,request,legacyBatch,memory,ordinal++);
            if(transport!=null&&mode==MetadataMode.FULL)for(var envelope:legacy){
                @SuppressWarnings("unchecked") var original=(Map<String,Object>)((Map<?,?>)envelope.get("@metadata")).get("splunk_hec");
                var metadata=new LinkedHashMap<>(original);metadata.put("tcp",transport);envelope.put("@metadata",Map.of("splunk_hec",metadata));
                protocol.validateLogicalSize(envelope,memory);
            }
            Map<String,Object> effective;
            if(legacy.isEmpty()){
                // A record the legacy path maps to zero events (for example a delimiter-only record) must not become a new
                // failure merely because an unrelated rule is enabled: only a stream-relevant identity may select it.
                try{effective=effective(record,token,request,protocol,memory);}
                catch(HecException unusable){
                    // Only identity/validation rejections (4xx) of a record the standard path ignores are skipped; resource
                    // pressure (503) must still tell the sender to retry rather than silently drop the record.
                    if(unusable.status>=500)throw unusable;
                    mapped.add(new Mapped(legacy,null));continue;
                }
            }else effective=legacy.getFirst();
            boolean selected=!record.structured()&&(record.flags()&S2SDecoder.METRIC)==0&&policy.select((String)effective.get("sourcetype"))!=null;
            if(selected){
                if(effective.get("host")==null||effective.get("source")==null){
                    // The standard path ignores a record with no events; lacking identity must not turn it into a rejection.
                    if(legacy.isEmpty()){mapped.add(new Mapped(legacy,null));continue;}
                    throw new HecException(400,6,"Selected S2S record requires source identity");
                }
                boolean positioned=record.sequence()>=0&&(record.offset()>0||record.offset()==0&&record.stream()!=0);
                if(positioned)Math.addExact(record.offset(),record.raw().length);
                String key=hash(Arrays.asList(namespace,token.identity(),effective.get("host"),effective.get("source"),effective.get("index"),effective.get("sourcetype"),record.channel(),record.stream()));
                if(!positioned)key=hash(List.of(key,batch));
                String receipt=hash(positioned&&record.raw().length>0?Arrays.asList(key,record.offset(),record.sequence()):List.of(key,batch,ordinal-1));
                var nativeMetadata=new TreeMap<>(record.meta());
                if(transport!=null){nativeMetadata.remove("resent");nativeMetadata.remove("resent_marker");}
                String content=hash(Arrays.asList(TokenStore.fingerprint(record.raw()),record.fields(),nativeMetadata,
                    record.time(),record.flags(),record.header(),record.timezone(),record.dateParts()));
                String prior=validatedReceipts.putIfAbsent(receipt,content);
                if(prior!=null&&!prior.equals(content))throw new HecException(400,6,"Conflicting S2S retry coordinates");
                long lines=record.raw().length==0||record.raw()[record.raw().length-1]!='\n'?1:0;
                for(byte value:record.raw())if(value=='\n')lines++;
                validatedLines+=lines;
            }else validatedLines+=legacy.size();
            if(validatedLines>limits.events())throw HecException.busy();
            mapped.add(new Mapped(legacy,effective));
        }
        int number=0,produced=0;boolean changed=false;
        long now=clock.getAsLong();
        for(String key:new ArrayList<>(pending.keySet())){Pending value=pending.get(key);
            if(now>=value.touched&&now-value.touched>=value.timeout){finish(key,pending,outbox,"timeout",memory);committed.remove(key);changed=true;}
        }
        for(var record:records){
            var legacy=mapped.get(number).legacy;
            var effective=mapped.get(number).effective;
            if(effective==null){number++;continue;} // legacy-ignored record with no usable identity
            String type=(String)effective.get("sourcetype");var rule=policy.select(type);
            String key=hash(Arrays.asList(namespace,token.identity(),effective.get("host"),effective.get("source"),effective.get("index"),type,record.channel(),record.stream()));
            String origin=hash(Arrays.asList(namespace,token.identity(),effective.get("host"),effective.get("source"),record.channel(),record.stream()));
            String sender=senderOf(namespace,token,effective);
            boolean positioned=record.sequence()>=0&&(record.offset()>0||record.offset()==0&&record.stream()!=0);
            // Positionless records never acquire invented cross-request stream stability.
            if(!positioned){key=hash(List.of(key,batch));origin=hash(List.of(origin,batch));}
            if(rule!=null&&!record.structured()&&(record.flags()&S2SDecoder.METRIC)==0){
                // A retried record must be recognised before it can close another stream of the same origin.
                var retryMeta=new TreeMap<>(record.meta());
                if(transport!=null){retryMeta.remove("resent");retryMeta.remove("resent_marker");}
                String retryReceipt=hash(positioned&&record.raw().length>0?Arrays.asList(key,record.offset(),record.sequence()):List.of(key,batch,number));
                String retryContent=hash(Arrays.asList(TokenStore.fingerprint(record.raw()),record.fields(),retryMeta,record.time(),record.flags(),record.header(),record.timezone(),record.dateParts()));
                String retrySeen=receipts.get(retryReceipt);
                if(retrySeen!=null){if(!retrySeen.equals(retryContent))throw new HecException(400,6,"Conflicting S2S retry coordinates");number++;continue;}
            }
            for(String other:new ArrayList<>(pending.keySet()))if(!other.equals(key)&&pending.get(other).origin.equals(origin)){
                finish(other,pending,outbox,"metadata-conflict",memory);committed.remove(other);changed=true;
            }
            if(legacy.isEmpty()&&!record.structured()&&(record.flags()&S2SDecoder.METRIC)==0&&rule==null){number++;continue;} // nothing to order or emit
            if(record.structured()||(record.flags()&S2SDecoder.METRIC)!=0||rule==null){
                if((record.structured()||(record.flags()&S2SDecoder.METRIC)!=0)&&pending.containsKey(key)){
                    finish(key,pending,outbox,"structured-transition",memory);committed.remove(key);changed=true;
                }
                Set<String> predecessors=new HashSet<>();
                for(var output:outbox)if(sender.equals(output.sender()))predecessors.add(output.id);
                if(gated.add(sender))barriers.addAll(predecessors);
                steps.add(new Direct(List.copyOf(legacy),Set.copyOf(predecessors)));
                direct.addAll(legacy);number++;continue;
            }
            if(effective.get("host")==null||effective.get("source")==null)throw new HecException(400,6,"Selected S2S record requires source identity");
            // Zero-length records can repeat at one coordinate; coordinates alone do not prove a retry.
            String receipt=hash(positioned&&record.raw().length>0?Arrays.asList(key,record.offset(),record.sequence()):List.of(key,batch,number));
            var nativeMetadata=new TreeMap<>(record.meta());
            if(transport!=null){nativeMetadata.remove("resent");nativeMetadata.remove("resent_marker");}
            String content=hash(Arrays.asList(TokenStore.fingerprint(record.raw()),record.fields(),nativeMetadata,record.time(),record.flags(),record.header(),record.timezone(),record.dateParts()));
            String attributes=hash(Arrays.asList(record.fields(),nativeMetadata,record.header(),record.timezone(),record.dateParts()));
            String seen=receipts.get(receipt);
            if(seen!=null){if(!seen.equals(content))throw new HecException(400,6,"Conflicting S2S retry coordinates");number++;continue;}
            changed=true;
            memory.charge(8192L+16L*record.raw().length);
            var base=new LinkedHashMap<>(effective);base.remove("event");base.remove("@metadata");
            if(mode==MetadataMode.FULL){
                Map<String,Object> provenance=new LinkedHashMap<>();
                if(effective.get("@metadata") instanceof Map<?,?> outer&&outer.get("splunk_hec") instanceof Map<?,?> original)
                    original.forEach((k,v)->{if(!k.equals("id"))provenance.put((String)k,v);});
                if(transport!=null)provenance.put("tcp",transport);
                base.put("@metadata",Map.of("splunk_hec",provenance));
            }
            Pending previous=pending.get(key);
            if(previous!=null){
                var old=S2SAssemblyStore.envelope(previous.envelope);old.remove("time");old.remove("@timestamp");old.remove("@metadata");
                var comparable=new LinkedHashMap<>(base);comparable.remove("time");comparable.remove("@timestamp");comparable.remove("@metadata");
                String reason=!old.equals(comparable)||!previous.attributes.equals(attributes)?"metadata-conflict":positioned&&record.offset()!=previous.offset?"coordinate-gap-or-reordering":
                    positioned&&record.sequence()<previous.sequence?"reordering":null;
                if(reason!=null){finish(key,pending,outbox,reason,memory);committed.remove(key);}
            }
            String text=HecProtocol.utf8(record.raw());int start=0,line=0,legacyLine=0;long rawCursor=0;
            boolean emptyRecord=text.isEmpty();
            while(start<text.length()||emptyRecord){
                emptyRecord=false;
                int lf=text.indexOf('\n',start),end=lf<0?text.length():lf;
                String delimiter=lf<0?"":end>start&&text.charAt(end-1)=='\r'?"\r\n":"\n";
                int contentEnd=end-(delimiter.equals("\r\n")?1:0);
                String value=text.substring(start,contentEnd);
                if(++produced>limits.events())throw HecException.busy();
                boolean begins=rule.start().matcher(value).find();
                if(begins&&pending.containsKey(key)){finish(key,pending,outbox,"new-start",memory);committed.remove(key);}
                Pending current=pending.get(key);
                if(current==null&&!begins){
                    if(!value.isEmpty())outbox.add(output(legacy.get(legacyLine),sender));
                }else{
                    String join=current==null?"":current.delimiter.isEmpty()?"\n":current.delimiter;
                    int prior=current==null?0:current.text.length();
                    if((long)prior+join.length()+value.length()+delimiter.length()>limits.event())rejectOversize(key,committed.contains(key));
                    // Charge only this line's incremental scratch; the retained state was already charged when admitted.
                    memory.charge(8192L+16L*(join.length()+value.length())+256L);
                    String assembled=(current==null?"":current.text)+join+value;
                    Map<String,Object> contribution=new LinkedHashMap<>();
                    contribution.put("offset",record.offset());contribution.put("sequence",record.sequence());contribution.put("line",(long)line);
                    contribution.put("logical_offset",record.offset()<0?-1:Math.addExact(record.offset(),rawCursor));
                    contribution.put("sha256",TokenStore.fingerprint((value+delimiter).getBytes(StandardCharsets.UTF_8)));
                    if(mode==MetadataMode.FULL)contribution.put("wire",S2SAssemblyStore.encode(wireProvenance(record)));
                    List<Object> contributions=current==null?new ArrayList<>():new ArrayList<>(current.contributions);contributions.add(contribution);
                    if(contributions.size()>limits.events())throw HecException.busy();
                    String chain=hash(List.of(current==null?key+rule.fingerprint():current.chain,receipt,content,line));
                    Object envelope=current==null?S2SAssemblyStore.encode(base):current.envelope;
                    Pending updated=new Pending(envelope,assembled,delimiter,rule.fingerprint(),chain,attributes,origin,List.copyOf(contributions),clock.getAsLong(),rule.timeout(),
                        positioned?Math.addExact(record.offset(),record.raw().length):-1,record.sequence(),limits.event(),sender);
                    // Include the final delimiter and full provenance in admission size checks.
                    try{completed(updated,"coordinate-gap-or-reordering",memory);}catch(AssembledEventTooLarge error){rejectOversize(key,committed.contains(key));}
                    pending.put(key,updated);
                }
                if(!value.isEmpty())legacyLine++;
                rawCursor+=(value+delimiter).getBytes(StandardCharsets.UTF_8).length;
                start=lf<0?text.length():lf+1;line++;
            }
            receipts.put(receipt,content);while(receipts.size()>receiptLimit)receipts.remove(receipts.keySet().iterator().next());
            if(pending.size()>maxStreams||outbox.size()>maxStreams*4L)throw HecException.busy();
            number++;
        }
        if(direct.size()+produced>limits.events())throw HecException.busy();
        if(!changed&&gated.isEmpty())return new Ordered(direct,null,steps);
        if(outbox.size()>maxStreams*4L)throw HecException.busy();
        // Raised before the monitor is first released, so the worker cannot dispatch later same-sender output early.
        Gate gate=gated.isEmpty()?null:new Gate(gated,barriers);
        if(gate!=null)gates.add(gate);
        try{
            if(changed){
                State next=new State(state.configuration,pending,outbox,receipts,false);
                validateFinalizationCapacity(next);persist(next);notifyAll();
            }
            // A structured transition preserves queue acceptance and follows its preceding completed tail.
            // Wait only for already completed output, never for a future source contribution.
            await(barriers);
        }catch(IOException|InterruptedException|RuntimeException error){release(gate);throw error;}
        return new Ordered(direct,gate,steps);
    }
    private void await(Set<String> predecessors)throws InterruptedException{
        while(state.outbox.stream().anyMatch(output->predecessors.contains(output.id))){
            if(stopped||blocked)throw HecException.busy();wait(50);
        }
    }
    private synchronized void release(Gate gate){if(gate!=null&&gates.remove(gate))notifyAll();}
    /** Sender of the current connection; HTTP requests without a channel cannot be told apart, so they fall back to the host. */
    private static String senderOf(String namespace,TokenStore.Token token,Map<String,Object> effective){
        return namespace.endsWith("/http:")?hash(Arrays.asList("host",namespace,token.identity(),effective.get("host"))):hash(List.of("sender",namespace,token.identity()));
    }
    private boolean held(Output output){
        if(output.sender()==null)return false;
        for(Gate gate:gates)if(gate.senders.contains(output.sender())&&!gate.ids.contains(output.id()))return true;
        return false;
    }
    /** First output that may be dispatched; a held output also holds every later output of its sender. */
    private Output next(){
        Set<String> skipped=new HashSet<>();
        for(Output output:state.outbox){
            String sender=output.sender();
            if(sender!=null&&skipped.contains(sender))continue;
            if(held(output)){if(sender!=null)skipped.add(sender);continue;}
            return output;
        }
        return null;
    }
    private Map<String,Object> effective(S2SDecoder.Event record,TokenStore.Token token,Map<String,String> request,HecProtocol protocol,MemoryBudget.Lease memory){
        Map<String,Object> envelope=new LinkedHashMap<>();envelope.put("event","");
        if(record.host()!=null)envelope.put("host",record.host());if(record.source()!=null)envelope.put("source",record.source());
        if(record.index()!=null)envelope.put("index",record.index());if(record.sourcetype()!=null)envelope.put("sourcetype",record.sourcetype());
        if(record.time()!=null)envelope.put("time",record.time());if(!record.fields().isEmpty())envelope.put("fields",record.fields());
        metadataFields.select(record.meta(),memory).apply(envelope,memory);
        return protocol.finalizeEnvelope(envelope,token,request,memory,record.time()==null?null:HecProtocol.epochSeconds(record.time()));
    }
    private static Map<String,Object> wireProvenance(S2SDecoder.Event record){
        var result=new LinkedHashMap<String,Object>();result.put("flags",record.flags());result.put("stream",Long.toUnsignedString(record.stream()));
        result.put("offset",record.offset());result.put("sequence",record.sequence());result.put("time",record.time());result.put("channel",record.channel());
        result.put("date_parts",record.dateParts().stream().map(p->Map.of("part",p.part(),"tag",p.tag(),"value",p.value())).toList());
        result.put("timezone",record.timezone());result.put("csv_header",record.header());result.put("wire_metadata",record.meta());return result;
    }
    private static String hash(Object value){try{return TokenStore.fingerprint(HecProtocol.JSON.writeValueAsBytes(canonical(value)));}catch(IOException error){throw HecException.invalid();}}
    private static Object canonical(Object value){
        if(value instanceof Map<?,?> map){Map<String,Object> sorted=new TreeMap<>();map.forEach((k,v)->sorted.put((String)k,canonical(v)));return sorted;}
        if(value instanceof List<?> list)return list.stream().map(S2SStreamAssembler::canonical).toList();return value;
    }
    // Journal occurrence identity is separate from the stable event ID. Identical NONE-mode
    // envelopes must not share a gate permit just because their serialized content matches.
    private static Output output(Map<String,Object> envelope,String sender){return new Output(UUID.randomUUID().toString(),S2SAssemblyStore.encode(envelope),sender);}
    private Map<String,Object> completed(Pending pending,String reason,MemoryBudget.Lease memory){
        var envelope=S2SAssemblyStore.envelope(pending.envelope);envelope.put("event",pending.text+pending.delimiter);
        String id="s2s-assembled-v1:"+hash(List.of(pending.chain,pending.rule,reason));
        if(mode!=MetadataMode.NONE){
            Map<String,Object> metadata=new LinkedHashMap<>();
            if(envelope.get("@metadata") instanceof Map<?,?> outer&&outer.get("splunk_hec") instanceof Map<?,?> existing)
                existing.forEach((k,v)->metadata.put((String)k,v));
            metadata.put("id",id);
            if(mode==MetadataMode.FULL){
                List<Object> contributions=new ArrayList<>();
                for(Object value:pending.contributions){
                    @SuppressWarnings("unchecked") var contribution=new LinkedHashMap<>((Map<String,Object>)value);
                    if(contribution.containsKey("wire"))contribution.put("wire",S2SAssemblyStore.decode(contribution.get("wire")));
                    contributions.add(contribution);
                }
                metadata.put("assembly",Map.of("flush_reason",reason,"rule",pending.rule,"contributions",contributions));
            }
            envelope.put("@metadata",Map.of("splunk_hec",metadata));
        }
        if(!HecProtocol.logicalSizeFits(envelope,memory,pending.eventLimit))throw new AssembledEventTooLarge();
        return envelope;
    }
    private void finish(String key,Map<String,Pending> pending,List<Output> outbox,String reason,MemoryBudget.Lease memory){
        Pending value=pending.get(key);if(value==null)return;
        outbox.add(output(completed(value,reason,memory),value.sender));pending.remove(key);
    }
    synchronized void expire(MemoryBudget.Lease memory)throws IOException{
        if(stopped||blocked)return;
        var pending=new LinkedHashMap<>(state.pending);var outbox=new ArrayList<>(state.outbox);
        long now=clock.getAsLong();
        for(String key:new ArrayList<>(pending.keySet())){Pending value=pending.get(key);
            if(now>=value.touched&&now-value.touched>=value.timeout)finish(key,pending,outbox,"timeout",memory);
        }
        if(outbox.size()>maxStreams*4L)throw HecException.busy();
        if(pending.size()!=state.pending.size())persist(new State(state.configuration,pending,outbox,state.receipts,false));
    }
    private void rejectOversize(String key,boolean durable)throws IOException{
        if(durable&&state.pending.containsKey(key)){
            persist(new State(state.configuration,state.pending,state.outbox,state.receipts,true));blocked=true;
            diagnostic.accept("S2S assembly blocked by oversized continuation; accepted state retained for explicit operator recovery");
        }
        throw HecException.busy();
    }
    private void persist(State next)throws IOException{
        try{store.commit(next);state=next;}
        catch(IOException error){
            if(store.failed()){blocked=true;failure="S2S assembly storage blocked; accepted state retained";diagnostic.accept(failure);notifyAll();}
            throw error;
        }
    }
    /**
     * Every subset of pending entries may become output before a single handoff frees space.
     * Reserve each positive replacement delta, including an output-array comma, before ACK.
     * The longest flush reason also bounds all other completion reasons (IDs have fixed length).
     */
    private void validateFinalizationCapacity(State next)throws IOException{
        if(next.outbox.size()+(long)next.pending.size()>maxStreams*4L)throw HecException.busy();
        long reserve=0;
        MemoryBudget scratch=new MemoryBudget(Long.MAX_VALUE);
        try(var memory=scratch.lease()){
            for(var entry:next.pending.entrySet()){
                Pending pending=entry.getValue();
                Output completed=output(completed(pending,"coordinate-gap-or-reordering",memory),pending.sender);
                long pendingBytes=store.serializedSize(Collections.singletonMap(entry.getKey(),pending))-2;
                reserve=Math.addExact(reserve,Math.max(0,store.serializedSize(completed)+1-pendingBytes));
            }
        }
        store.validateCapacity(next,reserve);
    }
    private void run(Consumer<Map<String,Object>> sink){
        // Scratch already covered by the permanent reservation, not charged to request leases.
        MemoryBudget scratch=new MemoryBudget(Long.MAX_VALUE);
        while(!stopped&&!blocked)try{
            Output output;
            synchronized(this){
                output=next();
                if(output==null){try(var memory=scratch.lease()){expire(memory);}output=next();}
            }
            if(output==null){synchronized(this){if(!stopped)wait(50);}continue;}
            sink.accept(S2SAssemblyStore.envelope(output.envelope));
            synchronized(this){
                if(stopped)break;
                var remaining=new ArrayList<>(state.outbox);
                for(int index=0;index<remaining.size();index++)if(remaining.get(index)==output){remaining.remove(index);break;}
                persist(new State(state.configuration,state.pending,remaining,state.receipts,state.blocked));
                notifyAll();
            }
        }catch(InterruptedException error){Thread.currentThread().interrupt();break;}
        catch(Exception error){
            if(!stopped){blocked=true;failure="S2S assembly blocked; durable state retained ("+error.getClass().getSimpleName()+")";diagnostic.accept(failure);}
            break;
        }
    }
    synchronized int pendingCount(){return state.pending.size();}
    synchronized int outputCount(){return state.outbox.size();}
    void beginStop(){stopped=true;Thread owned; synchronized(this){notifyAll();owned=worker;}if(owned!=null)owned.interrupt();}
    void closeBy(long deadline)throws IOException{
        beginStop();Thread owned=worker;
        boolean interrupted=Thread.interrupted();
        try{
            while(owned!=null&&owned.isAlive()){
                long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException("assembly worker still owned at shutdown deadline");
                try{owned.join(Math.max(1,java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(left)));}catch(InterruptedException error){interrupted=true;}
            }
            store.close();reservation.close();
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    @Override public void close()throws IOException{closeBy(System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(10));}
}
