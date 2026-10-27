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

/**
 * Defines the native envelope understood by the input: event, time, host, source,
 * sourcetype, index and indexed fields, plus required Logstash internals. JSON
 * transport decoding is not a content-processing filter: objects/arrays stay
 * native and raw text is not JSON-parsed, flattened or assigned a message field.
 *
 * <p>The /event grammar is one object, concatenated objects, or an array of
 * envelope objects. The /raw grammar is UTF-8 text with request-local LF/CRLF
 * framing. S2SEvents reuses envelope validation after its binary decoder has
 * already established wire record types, timestamps and references.
 */
public final class HecProtocol {
    /**
     * Prepared events plus an optional validation failure after a valid prefix.
     * No insertion happens here; HecServer owns queue writes and the response.
     * @param events native envelopes prepared in request order
     * @param failure error to return after prefix insertion, or null for full validation
     */
    public record Prepared(List<Map<String, Object>> events, HecException failure) {}
    private final Limits limits;
    private final JsonFactory json;
    static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Create the JSON parser with the input's nesting and logical-size constraints.
     * @param limits JSON nesting, event size/count and allocation bounds
     */
    public HecProtocol(Limits limits) {
        this.limits = limits;
        json = JsonFactory.builder().disable(JsonFactory.Feature.INTERN_FIELD_NAMES)
            .disable(JsonFactory.Feature.CANONICALIZE_FIELD_NAMES).streamReadConstraints(StreamReadConstraints.builder()
            .maxNestingDepth(limits.depth()).maxStringLength(limits.event()).maxNameLength(limits.event()).maxNumberLength(1024).build()).build();
    }
    /**
     * Parse public HEC event envelopes without running an application-data filter.
     * Valid prefixes can accompany oracle-compatible parse/field failures;
     * request resource-limit failures escape before the server begins insertion.
     * @param body HTTP entity bytes after optional gzip decoding
     * @param policy authenticated per-request token-policy snapshot
     * @param request query metadata, with only supported keys used as defaults
     * @param memory request allocation reservation shared with transport decoding
     * @return prepared native envelopes and any prefix validation failure
     */
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
            // A top-level array batches ENVELOPES. An array inside an envelope's
            // event property is instead one application payload, not a batch.
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
                    // Preserve measured oracle numbering: index errors are one-
                    // based, while the other recorded per-event errors are zero-based.
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
        // This restriction is only on the root event value. Nested application
        // booleans/nulls remain valid, as do strings/numbers/objects/arrays.
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
        // Only these four metadata names use query -> token/global fallback.
        // Explicit source time is handled separately; raw query time/fields are
        // not interpreted as event metadata by this implementation.
        for (String key : List.of("host", "source", "sourcetype", "index")) {
            Object v = out.containsKey(key) ? out.get(key) : request.getOrDefault(key, policy.defaults().get(key));
            if (v != null && !(v instanceof String)) throw HecException.invalid();
            if (out.containsKey(key) && v == null) throw HecException.invalid();
            if (v != null) out.put(key, v);
        }
        String index = (String) out.get("index");
        if (index == null || index.isEmpty() || (!policy.indexes().isEmpty() && !policy.indexes().contains(index)))
            throw new HecException(400, 7, "Incorrect index");
        // HEC indexed fields are a flat map (scalar multivalues allowed). That
        // constraint must not be applied to arbitrary nested event payloads.
        if (out.containsKey("fields")) {
            if (!(out.get("fields") instanceof Map<?, ?> fields)) throw new HecException(400, 15, "Error in handling indexed fields");
            for (Object v : fields.values()) {
                if (v instanceof Map<?, ?> || (v instanceof List<?> l && l.stream().anyMatch(x -> x instanceof Map<?, ?> || x instanceof List<?>)))
                    throw new HecException(400, 15, "Error in handling indexed fields");
            }
        }
        // Application payloads may contain these literal keys inside event/fields,
        // but the envelope root cannot overwrite the runtime's bookkeeping.
        if (out.containsKey("@timestamp") || out.containsKey("@metadata") || out.containsKey("@version"))
            throw HecException.invalid();
        // Native S2S seconds bypass HEC unit inference. Keep the supplied source
        // time in the envelope independently of this internal Timestamp object.
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
    /**
     * Prepare values for Logstash's Event/PQ model without silent numeric loss.
     * Large integers/decimals retain BigInteger/BigDecimal. Container copies are
     * reserved before allocation because one S2S field map can feed many lines.
     */
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
    /** HEC time interpretation only; binary S2S carries explicitly native epoch seconds. */
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
    /**
     * Decode the whole raw body before insertion; framing state is request-local.
     * @param body UTF-8 text bytes after optional HTTP gzip decoding
     * @param policy authenticated token defaults and index restrictions
     * @param request supported request-level host/source/sourcetype/index metadata
     * @param memory allocation reservation for text, framing and envelope copies
     * @return prepared text envelopes, including an empty list for no logical lines
     */
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
    // Empty delimiter records are skipped; whitespace-only nonempty lines and an
    // unterminated tail remain. Indentation and JSON-looking text have no extra meaning.
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
