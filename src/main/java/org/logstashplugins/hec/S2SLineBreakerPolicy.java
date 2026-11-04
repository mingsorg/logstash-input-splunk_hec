package org.logstashplugins.hec;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.google.re2j.Pattern;
import java.util.*;

/** Immutable, startup-only selectors. RE2 bounds both selector and start matching. */
final class S2SLineBreakerPolicy {
    record Rule(String mode,String selector,Pattern glob,Pattern start,long timeout,String fingerprint) {}
    static final S2SLineBreakerPolicy EMPTY=parse("[]");
    private final Map<String,Rule> exact;
    private final List<Rule> globs;
    final String fingerprint;
    private S2SLineBreakerPolicy(Map<String,Rule> exact,List<Rule> globs,String fingerprint){
        this.exact=Map.copyOf(exact);this.globs=List.copyOf(globs);this.fingerprint=fingerprint;
    }
    boolean enabled(){return !exact.isEmpty()||!globs.isEmpty();}
    Rule select(String type){
        if(type==null)return null;
        Rule rule=exact.get(type);if(rule!=null)return rule;
        for(Rule candidate:globs)if(candidate.glob.matcher(type).matches())return candidate;
        return null;
    }
    static S2SLineBreakerPolicy parse(String text){
        try{
            if(text==null||text.length()>65536)throw new IllegalArgumentException();
            var factory=JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(4).maxStringLength(4096).build()).build();
            var mapper=new ObjectMapper(factory);
            JsonNode root;
            try(var parser=factory.createParser(text)){root=mapper.readTree(parser);if(parser.nextToken()!=null)throw new IllegalArgumentException();}
            if(root==null||!root.isArray()||root.size()>128)throw new IllegalArgumentException();
            Map<String,Rule> exact=new LinkedHashMap<>();List<Rule> globs=new ArrayList<>();Set<String> selectors=new HashSet<>();
            List<Object> canonical=new ArrayList<>();
            for(JsonNode node:root){
                if(!node.isObject()||node.size()!=4)throw new IllegalArgumentException();
                for(String key:List.of("match","sourcetype","event_start_pattern"))
                    if(!node.has(key)||!node.get(key).isTextual()||node.get(key).asText().isBlank()||node.get(key).asText().length()>4096)throw new IllegalArgumentException();
                String mode=node.get("match").asText(),selector=HecProtocol.unicode(node.get("sourcetype").asText());
                String pattern=HecProtocol.unicode(node.get("event_start_pattern").asText());
                if(!mode.equals("exact")&&!mode.equals("glob")||!selectors.add(mode+":"+selector))throw new IllegalArgumentException();
                JsonNode timeout=node.get("flush_timeout_ms");
                if(timeout==null||!timeout.isIntegralNumber()||!timeout.canConvertToLong()||timeout.longValue()<=0)throw new IllegalArgumentException();
                var identity=List.of(mode,selector,pattern,timeout.longValue());canonical.add(identity);
                Rule rule=new Rule(mode,selector,mode.equals("glob")?Pattern.compile(glob(selector)):null,
                    Pattern.compile(pattern),timeout.longValue(),TokenStore.fingerprint(mapper.writeValueAsBytes(identity)));
                if(mode.equals("exact"))exact.put(selector,rule);else globs.add(rule);
            }
            return new S2SLineBreakerPolicy(exact,globs,TokenStore.fingerprint(mapper.writeValueAsBytes(canonical)));
        }catch(Exception failure){throw new IllegalArgumentException("invalid s2s_line_breaker_rules_json: expected bounded unique exact/glob rules, RE2 patterns and positive integer timeouts");}
    }
    private static String glob(String selector){
        StringBuilder result=new StringBuilder("(?s)");
        for(int i=0;i<selector.length();){
            int c=selector.codePointAt(i);i+=Character.charCount(c);
            result.append(c=='*'?".*":c=='?'?".":Pattern.quote(new String(Character.toChars(c))));
        }
        return result.toString();
    }
}
