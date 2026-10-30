package org.logstashplugins.hec;

import com.fasterxml.jackson.core.*;
import java.io.IOException;
import java.util.*;

/**
 * Startup-only allowlist from exact decoded per-record wire keys to literal
 * names inside s2s_metadata. It never reads indexed fields or handshake facts.
 * Parse into local state and publish only an immutable, completely valid policy.
 */
final class S2SMetadataFields {
    static final S2SMetadataFields EMPTY=new S2SMetadataFields(Map.of());
    private static final JsonFactory JSON=JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    private final Map<String,String> mapping;

    private S2SMetadataFields(Map<String,String> mapping){
        this.mapping=Collections.unmodifiableMap(new LinkedHashMap<>(mapping));
    }

    static S2SMetadataFields parse(String text){
        try(JsonParser parser=JSON.createParser(text)){
            if(parser.nextToken()!=JsonToken.START_OBJECT)throw invalid();
            Map<String,String> mapping=new LinkedHashMap<>();
            Set<String> destinations=new HashSet<>();
            while(parser.nextToken()!=JsonToken.END_OBJECT){
                if(parser.currentToken()!=JsonToken.FIELD_NAME)throw invalid();
                String source=HecProtocol.unicode(parser.currentName());
                if(source.isBlank()||parser.nextToken()!=JsonToken.VALUE_STRING)throw invalid();
                String destination=parser.getText();
                // No dots, brackets, escapes-as-paths or runtime field-reference syntax.
                if(!destination.matches("[A-Za-z_][A-Za-z0-9_]*")||!destinations.add(destination))throw invalid();
                mapping.put(source,destination);
            }
            if(parser.nextToken()!=null)throw invalid();
            return mapping.isEmpty()?EMPTY:new S2SMetadataFields(mapping);
        }catch(IOException|RuntimeException failure){
            // Jackson diagnostics can contain configured names/values and source
            // snippets. Do not retain the exception as a cause or echo its text.
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid(){
        return new IllegalArgumentException("s2s_metadata_fields_json requires a JSON object of unique nonblank source names and unique simple destination identifiers ([A-Za-z_][A-Za-z0-9_]*) with string values");
    }

    Selected select(Map<String,String> metadata,MemoryBudget.Lease memory){
        Map<String,String> selected=null;long charge=0;
        // Resolve exact matches once per wire record, rather than rescanning the
        // entire configured allowlist for every logical line in a UF record.
        for(var entry:mapping.entrySet()){
            String value=metadata.get(entry.getKey());
            if(value==null)continue;
            long entryCharge=96L+2L*entry.getValue().length()+2L*value.length();
            memory.charge(entryCharge+(selected==null?64L:0));
            if(selected==null)selected=new LinkedHashMap<>();
            selected.put(entry.getValue(),value);charge+=entryCharge;
        }
        if(selected==null)return Selected.EMPTY; // Default/no match: no namespace or allocation.
        memory.charge(32);
        return new Selected(selected,charge);
    }

    static final class Selected {
        private static final Selected EMPTY=new Selected(Map.of(),0);
        private final Map<String,String> values;
        private final long charge;
        private Selected(Map<String,String> values,long charge){this.values=values;this.charge=charge;}
        void apply(Map<String,Object> envelope,MemoryBudget.Lease memory){
            if(values.isEmpty())return;
            // Each logical event still owns an independently reserved container.
            // Immutable decoded strings may be shared, but conservative string
            // charges also bound multiline amplification before any copy occurs.
            memory.charge(64L+charge);
            envelope.put("s2s_metadata",new LinkedHashMap<>(values));
        }
    }
}
