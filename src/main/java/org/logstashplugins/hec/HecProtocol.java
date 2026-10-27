package org.logstashplugins.hec;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.time.Instant;
import java.util.*;
import org.logstash.Timestamp;

public final class HecProtocol {
    public record Prepared(List<Map<String, Object>> events, HecException failure) {}
    private final Limits limits;
    private final JsonFactory json;
    static final ObjectMapper JSON = new ObjectMapper();

    public HecProtocol(Limits limits) {
        this.limits = limits;
        json = JsonFactory.builder().disable(JsonFactory.Feature.INTERN_FIELD_NAMES)
            .disable(JsonFactory.Feature.CANONICALIZE_FIELD_NAMES).streamReadConstraints(StreamReadConstraints.builder()
            .maxNestingDepth(limits.depth()).maxStringLength(limits.event()).maxNameLength(limits.event()).maxNumberLength(1024).build()).build();
    }
    public Prepared events(byte[] body, TokenStore.Token policy, Map<String, String> request, MemoryBudget.Lease memory) {
        // Reserve parser scratch before Jackson can allocate a maximum-size token.
        memory.charge(4L * limits.event()+32768);
        int valid=validUtf8Prefix(body);
        boolean badEncoding=valid<body.length;
        if(badEncoding){memory.charge(valid);body=Arrays.copyOf(body,valid);}
        List<Map<String, Object>> events = new ArrayList<>();
        int number = 0;
        try (JsonParser p = json.createParser(body)) {
            JsonToken t = p.nextToken();
            if (t == null) return new Prepared(events,badEncoding?new HecException(400,6,"Invalid data format",0):new HecException(400, 5, "No data"));
            boolean array = t == JsonToken.START_ARRAY;
            if (array) t = p.nextToken();
            while (t != null && (!array || t != JsonToken.END_ARRAY)) {
                if (events.size() >= limits.events()) throw HecException.busy();
                Object value = value(p, t, memory);
                if (!(value instanceof Map<?, ?>)) throw HecException.invalid();
                @SuppressWarnings("unchecked") Map<String, Object> envelope = (Map<String, Object>) value;
                try { events.add(prepare(envelope, policy, request, memory)); }
                catch (HecException e) {
                    if (e.code == 9) throw e;
                    return new Prepared(events, new HecException(e.status, e.code, e.getMessage(), e.code == 7 ? number+1 : number));
                }
                number++;
                t = p.nextToken();
            }
            if (array && (t != JsonToken.END_ARRAY || p.nextToken() != null)) throw HecException.invalid();
            if (events.isEmpty()) return new Prepared(events, HecException.invalid());
            return new Prepared(events,badEncoding?new HecException(400,6,"Invalid data format",number):null);
        } catch (HecException e) {
            if (e.code == 9) throw e;
            return new Prepared(events, new HecException(400, e.code, e.getMessage(), number));
        } catch (IOException | IllegalArgumentException e) {
            return new Prepared(events, new HecException(400, 6, "Invalid data format", number));
        }
    }
    private Object value(JsonParser p, JsonToken token, MemoryBudget.Lease memory) throws IOException {
        memory.charge(512);
        return switch (token) {
            case START_OBJECT -> {
                Map<String, Object> m = new LinkedHashMap<>();
                while (p.nextToken() != JsonToken.END_OBJECT) {
                    if (p.currentToken() != JsonToken.FIELD_NAME) throw HecException.invalid();
                    String key = unicode(p.currentName()); memory.charge(256L + key.length()*2L);
                    m.put(key, value(p, p.nextToken(), memory)); // observed last-key-wins
                }
                yield m;
            }
            case START_ARRAY -> {
                List<Object> list = new ArrayList<>();
                JsonToken next;
                while ((next = p.nextToken()) != JsonToken.END_ARRAY) {
                    if (next == null) throw HecException.invalid();
                    list.add(value(p, next, memory));
                }
                yield list;
            }
            case VALUE_STRING -> { String s = unicode(p.getText()); memory.charge(64L + 2L*s.length()); yield s; }
            case VALUE_NUMBER_INT -> p.getBigIntegerValue();
            case VALUE_NUMBER_FLOAT -> {
                BigDecimal number=p.getDecimalValue();
                yield number.signum()==0&&p.getText().startsWith("-")?-0.0:number;
            }
            case VALUE_TRUE -> true;
            case VALUE_FALSE -> false;
            case VALUE_NULL -> null;
            default -> throw HecException.invalid();
        };
    }
    List<Long> acknowledgments(byte[] body,MemoryBudget.Lease memory){
        memory.charge(4L*limits.event()+32768);if(validUtf8Prefix(body)!=body.length)throw HecException.invalid();
        try(JsonParser parser=json.createParser(body)){
            Object root=value(parser,parser.nextToken(),memory);
            if(parser.nextToken()!=null||!(root instanceof Map<?,?> map)||!(map.get("acks") instanceof List<?> list)||list.isEmpty()||list.size()>limits.events())throw HecException.invalid();
            List<Long> ids=new ArrayList<>();
            for(Object item:(List<?>)((Map<?,?>)root).get("acks")){
                if(!(item instanceof BigInteger n)||n.signum()<0||n.compareTo(BigInteger.valueOf(AckManager.MAX_ID))>0)throw HecException.invalid();
                ids.add(((BigInteger)item).longValueExact());
            }
            return ids;
        }catch(IOException|IllegalArgumentException|NullPointerException e){throw HecException.invalid();}
    }
    Map<String, Object> prepare(Map<String, Object> envelope, TokenStore.Token policy,
                                Map<String, String> request, MemoryBudget.Lease memory) {
        if (!envelope.containsKey("event")) throw new HecException(400, 12, "Event field is required");
        Object event = envelope.get("event");
        if (event == null || event instanceof Boolean) throw HecException.invalid();
        if (event instanceof String s && s.isBlank()) throw new HecException(400, 13, "Event field cannot be blank");
        return finalizeEnvelope(envelope, policy, request, memory);
    }
    Map<String, Object> finalizeEnvelope(Map<String, Object> envelope, TokenStore.Token policy,
                                          Map<String, String> request, MemoryBudget.Lease memory) {
        return finalizeEnvelope(envelope, policy, request, memory, null);
    }
    Map<String, Object> finalizeEnvelope(Map<String, Object> envelope, TokenStore.Token policy,
                                          Map<String, String> request, MemoryBudget.Lease memory, Timestamp nativeTime) {
        memory.charge(64L + 96L * envelope.size());
        Map<String, Object> out = new LinkedHashMap<>(envelope);
        for (String key : List.of("host", "source", "sourcetype", "index")) {
            Object v = out.containsKey(key) ? out.get(key) : request.getOrDefault(key, policy.defaults().get(key));
            if (v != null && !(v instanceof String)) throw HecException.invalid();
            if (out.containsKey(key) && v == null) throw HecException.invalid();
            if (v != null) out.put(key, v);
        }
        String index = (String) out.get("index");
        if (index == null || index.isEmpty() || (!policy.indexes().isEmpty() && !policy.indexes().contains(index)))
            throw new HecException(400, 7, "Incorrect index");
        if (out.containsKey("fields")) {
            if (!(out.get("fields") instanceof Map<?, ?> fields)) throw new HecException(400, 15, "Error in handling indexed fields");
            for (Object v : fields.values()) {
                if (v instanceof Map<?, ?> || (v instanceof List<?> l && l.stream().anyMatch(x -> x instanceof Map<?, ?> || x instanceof List<?>)))
                    throw new HecException(400, 15, "Error in handling indexed fields");
            }
        }
        if (out.containsKey("@timestamp") || out.containsKey("@metadata") || out.containsKey("@version"))
            throw HecException.invalid();
        Timestamp timestamp = nativeTime;
        if (timestamp == null && out.containsKey("time")) timestamp = timestamp(out.get("time"));
        @SuppressWarnings("unchecked") Map<String, Object> safe = (Map<String, Object>) lossless(out, memory);
        validateLogicalSize(safe, memory);
        if (timestamp != null) safe.put("@timestamp", timestamp);
        return safe;
    }
    void validateLogicalSize(Map<String,Object> event, MemoryBudget.Lease memory) {
        Map<String,Object> sized = event;
        if (event.containsKey("@timestamp") || event.containsKey("@version")) {
            memory.charge(64L + 96L * event.size());
            sized = new LinkedHashMap<>(event);
            sized.remove("@timestamp"); sized.remove("@version");
        }
        try {
            // Account for serialization scratch/copy before allocating, then enforce logical byte cap.
            // Bound serialization while writing; never allocate an oversized serialized copy.
            JSON.writeValue(new OutputStream(){
                private long written;
                @Override public void write(int b){if(++written>limits.event())throw HecException.busy();}
                @Override public void write(byte[] b,int off,int length){
                    if(length>limits.event()-written)throw HecException.busy();written+=length;
                }
            },sized);
        } catch (IOException e) {
            for(Throwable cause=e;cause!=null;cause=cause.getCause())if(cause instanceof HecException failure)throw failure;
            throw HecException.invalid();
        }
    }
    static Object lossless(Object value, MemoryBudget.Lease memory) {
        if(value instanceof String s)return unicode(s);
        if (value instanceof BigInteger i) {
            try { return i.longValueExact(); } catch (ArithmeticException e) { return i; }
        }
        if (value instanceof BigDecimal d) {
            // Logstash 9.5+ preserves BigDecimal through Valuefier and PQ CBOR.
            // Keep ordinary exact doubles compact, without rejecting decimal data
            // merely because it has no finite binary floating-point expansion.
            if (Math.abs((long)d.scale()) > 1024 || d.precision() > 1024) throw HecException.invalid();
            double n = d.doubleValue();
            return Double.isFinite(n) && new BigDecimal(n).compareTo(d) == 0 ? n : d;
        }
        if (value instanceof Double d && !Double.isFinite(d)) throw HecException.invalid();
        if (value instanceof Map<?, ?> m) {
            memory.charge(64L + 96L * m.size());
            Map<String, Object> copy = new LinkedHashMap<>();
            m.forEach((k,v) -> copy.put((String) k, lossless(v, memory))); return copy;
        }
        if (value instanceof List<?> l) {
            memory.charge(32L + 24L * l.size());
            List<Object> copy = new ArrayList<>(l.size()); for (Object v : l) copy.add(lossless(v, memory)); return copy;
        }
        return value;
    }
    static Timestamp timestamp(Object value) {
        try {
            if (!(value instanceof String || value instanceof Number)) throw HecException.invalid();
            String literal=value.toString();if(literal.length()>1024)throw HecException.invalid();
            BigDecimal n = new BigDecimal(literal);
            if(Math.abs((long)n.scale())>1024)throw HecException.invalid();
            BigDecimal abs = n.abs();
            long digits = (long)n.precision() - n.scale();
            if (abs.compareTo(BigDecimal.TEN.pow(10)) >= 0) {
                n = n.movePointLeft(digits <= 13 ? 3 : digits <= 16 ? 6 : 9);
            }
            return epochSeconds(n);
        } catch (RuntimeException e) { throw HecException.invalid(); }
    }
    static Timestamp epochSeconds(String value){
        if(value.length()>1024)throw HecException.invalid();
        try{return epochSeconds(new BigDecimal(value));}catch(RuntimeException e){throw HecException.invalid();}
    }
    private static Timestamp epochSeconds(BigDecimal n){
        try{
            if(Math.abs((long)n.scale())>1024||n.precision()>1024)throw HecException.invalid();
            n=n.stripTrailingZeros();
            if(n.scale()>9||(long)n.precision()-n.scale()>19)throw HecException.invalid();
            BigDecimal seconds=n.setScale(0,java.math.RoundingMode.FLOOR);
            return new Timestamp(Instant.ofEpochSecond(seconds.longValueExact(),n.subtract(seconds).movePointRight(9).intValueExact()));
        }catch(RuntimeException e){throw HecException.invalid();}
    }
    public Prepared raw(byte[] body, TokenStore.Token policy, Map<String, String> request, MemoryBudget.Lease memory) {
        memory.charge(8L*body.length + 4L*limits.event() + 1024L*Math.min(limits.events(),(long)body.length+1));
        String text = utf8(body);
        List<Map<String, Object>> events = new ArrayList<>();
        for (String line : lines(text, limits.events())) {
            if (events.size() >= limits.events()) throw HecException.busy();
            // Raw whitespace-only records are intentional; event endpoint blank validation does not apply.
            events.add(finalizeEnvelope(Map.of("event", line), policy, request, memory));
        }
        return new Prepared(events, null);
    }
    static List<String> lines(String text) {
        return lines(text, 10_000);
    }
    static List<String> lines(String text, int maximum) {
        List<String> lines = new ArrayList<>();
        int start = 0;
        for (int i=0; i<text.length(); i++) if (text.charAt(i)=='\n') {
            int end = i > start && text.charAt(i-1)=='\r' ? i-1 : i;
            if (end > start) {
                if (lines.size() >= maximum) throw HecException.busy();
                lines.add(text.substring(start,end));
            }
            start = i+1;
        }
        if (start < text.length()) {
            if (lines.size() >= maximum) throw HecException.busy();
            lines.add(text.substring(start));
        }
        return lines;
    }
    static String utf8(byte[] bytes) {
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
        catch (CharacterCodingException e) { throw HecException.invalid(); }
    }
    private static int validUtf8Prefix(byte[] bytes){
        CharsetDecoder decoder=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer input=ByteBuffer.wrap(bytes);CharBuffer output=CharBuffer.allocate(8192);
        for(;;){
            CoderResult result=decoder.decode(input,output,true);
            if(result.isError())return input.position();
            if(result.isUnderflow())return bytes.length;
            output.clear();
        }
    }
    static String unicode(String text){
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            if(Character.isHighSurrogate(c)){
                if(++i>=text.length()||!Character.isLowSurrogate(text.charAt(i)))throw HecException.invalid();
            }else if(Character.isLowSurrogate(c))throw HecException.invalid();
        }
        return text;
    }
}
