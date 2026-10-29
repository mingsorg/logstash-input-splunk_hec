package org.logstashplugins.hec;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Interprets decoded wire records as the native envelopes handed to Logstash.
 * Decoding and event framing are separate: a structured record is one event,
 * while an unstructured UF record may contain several complete lines. The
 * structured flag, not an assumed UF/HF product type, selects that behavior.
 *
 * <p>Output keeps event/time/host/source/sourcetype/index/fields. Protocol flags,
 * channels and source coordinates live under {@code @metadata.splunk_hec}; no
 * message/ECS fields or raw-text timestamp extraction are introduced here.
 * The caller prepares this entire list before any queue insertion.
 */
final class S2SEvents {
    private final Limits limits;
    private final HecProtocol protocol;
    private final MetadataMode mode;
    S2SEvents(Limits limits,HecProtocol protocol){this(limits,protocol,MetadataMode.FULL);}
    S2SEvents(Limits limits,HecProtocol protocol,MetadataMode mode){this.limits=limits;this.protocol=protocol;this.mode=mode;}
    List<Map<String,Object>> map(List<S2SDecoder.Event> records,TokenStore.Token token,
                                  Map<String,String> request,byte[] batch,MemoryBudget.Lease memory){
        return mapWithIdentity(records,token,request,TokenStore.fingerprint(batch),memory);
    }
    List<Map<String,Object>> mapWithIdentity(List<S2SDecoder.Event> records,TokenStore.Token token,
                                  Map<String,String> request,String batchIdentity,MemoryBudget.Lease memory){
        List<Map<String,Object>> out=new ArrayList<>();
        // HTTP supplies its entity digest; TCP supplies one decoded wire-record
        // digest without retaining an extra copy. Missing-coordinate identities
        // promise exact batch/record replay, not arbitrary rebatching stability.
        memory.charge(4L*limits.event());
        int recordNumber=0;
        for(S2SDecoder.Event record:records){
            memory.charge(8L*record.raw().length+1024L*Math.min(limits.events(),(long)record.raw().length+1));
            String text=HecProtocol.utf8(record.raw());
            // UF raw records terminate logical lines even when their last newline
            // was stripped on the wire. Never join the tail to the next record or
            // infer continuation from indentation. Structured embedded newlines stay.
            List<String> lines=record.structured()?List.of(text):HecProtocol.lines(text,limits.events());
            int rawCursor=0, lineNumber=0;
            // Stream=0/offset=0 can describe data without a file position. Treating
            // it as a unique source coordinate could collapse legitimate repeats.
            boolean positioned=record.sequence()>=0 && (record.offset()>0 || record.offset()==0 && record.stream()!=0);
            for(String line:lines){
                if(!record.structured()){
                    while(rawCursor<record.raw().length && (record.raw()[rawCursor]=='\n' ||
                        record.raw()[rawCursor]=='\r' && rawCursor+1<record.raw().length && record.raw()[rawCursor+1]=='\n')) rawCursor++;
                }
                // rawCursor counts original UTF-8 bytes, including skipped CRLF/
                // empty delimiters. This keeps source positions stable on rebatching.
                long byteOffset=record.offset()+rawCursor;
                if(out.size()>=limits.events())throw HecException.busy();
                memory.charge(2048L+8L*line.length());
                Map<String,Object> envelope=new LinkedHashMap<>();envelope.put("event",line);
                if(record.host()!=null)envelope.put("host",record.host());
                if(record.source()!=null)envelope.put("source",record.source());
                if(record.sourcetype()!=null)envelope.put("sourcetype",record.sourcetype());
                if(record.index()!=null)envelope.put("index",record.index());
                if(record.time()!=null)envelope.put("time",record.time());
                // Indexed names, even "host" or "message", stay inside fields and
                // cannot overwrite host/source metadata from the wire tuple.
                if(!record.fields().isEmpty())envelope.put("fields",record.fields());
                // S2S time is explicitly epoch SECONDS. Bypass HEC's large-integer
                // ms/us/ns inference, which would misread future native seconds.
                Map<String,Object> event=protocol.finalizeEnvelope(envelope,token,request,memory,
                    record.time()==null?null:HecProtocol.epochSeconds(record.time()));
                if(mode!=MetadataMode.NONE){
                    // Preserve protocol interpretation separately from the searchable
                    // envelope. Typical outputs omit @metadata after filters use it.
                    Map<String,Object> provenance=new LinkedHashMap<>();
                    provenance.put("flags",record.flags());provenance.put("stream",record.stream()<0?Long.toUnsignedString(record.stream()):record.stream());
                    provenance.put("offset",record.offset());provenance.put("sequence",record.sequence());
                    provenance.put("logical_offset",byteOffset);provenance.put("logical_line",lineNumber);
                    if(record.channel()!=null)provenance.put("channel",record.channel());
                    provenance.put("date_parts",record.dateParts().stream().map(p->Map.of("part",p.part(),"tag",p.tag(),"value",p.value())).toList());
                    if(record.timezone()!=null)provenance.put("timezone",record.timezone());
                    provenance.put("csv_header",record.header());provenance.put("wire_metadata",record.meta());
                    String basis;
                    try {
                        // Labeled versioned, length-delimited canonical JSON. No receipt/connection facts.
                        List<Object> identity=new ArrayList<>(Arrays.asList("s2s-id-v1",token.identity(),
                            record.host(),record.source(),record.sourcetype(),record.channel(),record.index(),
                             record.stream(),byteOffset,record.sequence(),positioned?0:lineNumber,line));
                        // Field order is not identity, but changed measurements/indexed
                        // values are changed content. Ordered multivalues remain ordered.
                        identity.add(new TreeMap<>(record.fields()));
                        identity.add(record.structured()?record.time():null);
                         if(!positioned){
                            identity.add(batchIdentity);
                            identity.add(recordNumber);provenance.put("identity_scope","identical-batch-retry");
                        }else provenance.put("identity_scope","source-coordinates");
                        basis=HecProtocol.JSON.writeValueAsString(identity);
                    }catch(Exception e){throw HecException.invalid();}
                    String id="s2s-v1:"+TokenStore.fingerprint(basis);
                    event.put("@metadata",mode==MetadataMode.FULL?Map.of("splunk_hec",Map.of("id",id,"s2s",provenance)):Map.of("splunk_hec",Map.of("id",id)));
                }
                // Validate again AFTER attaching source-derived provenance; large
                // headers/timezone/date-part lists must not bypass the logical cap.
                protocol.validateLogicalSize(event,memory);
                out.add(event);
                // Keep byte positions, including skipped leading delimiters and multibyte text.
                rawCursor+=line.getBytes(StandardCharsets.UTF_8).length;
                lineNumber++;
            }
            recordNumber++;
        }
        return out;
    }
}
