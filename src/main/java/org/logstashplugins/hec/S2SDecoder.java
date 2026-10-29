/*
 * Wire decoder ported from mingshsg/elastic-ingest-splunk-forwarders,
 * revision 1280a8e16a30a979d9dde1ff0328ee7d32b0ce99 (Apache-2.0).
 * MODIFIED: standalone Java, strict UTF-8/references/varints, complete-batch rejection,
 * bounded allocations, no salvage, no Elasticsearch dependencies or time truncation.
 */
package org.logstashplugins.hec;

import java.io.*;
import java.math.BigDecimal;
import java.nio.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Decodes observed UF/HF compact records, not HEC JSON. The default entry point
 * handles HTTP; StreamSession shares typed fields with a distinct TCP header.
 * The format described here is implemented from the pinned reference and wire
 * fixtures; it is not a claim to know every Splunk flag or historical variant.
 * See {@code docs/s2s-wire-format.md} for annotated bytes and bit diagrams.
 *
 * <p>Notation: U = unsigned base-128 varint, S = UTF-8 byte-length + bytes,
 * NS = nullable string (length + 1; zero means null), B = byte-length + bytes.
 * After the F9 body marker and zlib inflation, the stream is a sequence of:
 * <pre>
 * FF | S(timezone serialization)
 * FE | U(metaId) | NS(source) | NS(host) | NS(sourcetype) | NS(channel)
 *    | U(headerCount) | S(header[0]) ...
 * F8 | U(1) | the same metadata tuple beginning with U(metaId)
 * FC | U(metaId) | U(flags) | optional time/stream block
 *    | U(fieldCount) | typed fields ... | payload blob(s)
 * </pre>
 *
 * <p>There is no generic record-length prefix: each opcode's grammar determines
 * where the next record begins. Field values/raw data may contain opcode-looking
 * bytes, so scanning for FC/FE would corrupt framing. A decoding failure escapes
 * before the caller inserts any S2S events; this class never salvages a prefix or
 * queues replacement events. Allocation limits can independently report busy.
 */
public final class S2SDecoder {
    // Flags are decoded varint integers, not fixed-width bytes on the wire.
    // For HTTP: bit 6 means structured, either of
    // bits 1/3 supplies ALL four time/stream varints, and bit 16 adds a metric blob.
    // Other bits are retained as flags; their individual meanings are not guessed.
    static final int STRUCTURED=0x40, TIME_OR_STREAM=0x0a, METRIC=0x10000;
    // In the captured compact TCP profile these header bits are independent.
    // HTTP retains its original four-varint TIME_OR_STREAM grammar below.
    static final int TCP_STREAM_POS=0x02, TCP_EVENT_ID=0x04, TCP_TIMESTAMP=0x08;
    /**
     * Field tag seen only on records a forwarder RETRANSMITS after its acknowledgement wait expired.
     * Wire form: tag 0x46, U(marker), S("resent"). It is recorded as provenance and is never an indexed
     * field. Because it falls in the date-part tag range, it must be matched BEFORE the date-part branch.
     */
    static final int TCP_RESENT=0x46;
    /**
     * Original timestamp component; only part 0 drives fractional time here.
     * @param part observed component ID, with zero identifying subsecond encoding
     * @param tag decoded date tag, including sign/variant bits
     * @param value signed component value or shared constant ID, not calendar-normalized
     */
    public record DatePart(int part, int tag, long value) {}
    /**
     * One decoded wire record, before line framing and Logstash envelope creation.
     * Raw-reference offsets are relative to {@code raw}; {@code offset} is instead
     * a source-stream coordinate. Time is source epoch seconds plus decoded
     * decimal fraction, never a timestamp extracted from the raw log message.
     *
     * @param host host from the referenced metadata tuple, with host:: removed
     * @param source source from the tuple, with source:: removed
     * @param sourcetype sourcetype from the tuple, with sourcetype:: removed
     * @param channel S2S tuple channel, separate from the HTTP ACK GUID
     * @param index per-record _MetaData:Index value, or null for downstream defaults
     * @param flags decoded event-mask integer, including uninterpreted bits
     * @param stream uint64 identifier bits carried in a Java long
     * @param offset source byte coordinate, initialized to -1 when the block is absent
     * @param sequence source sequence, initialized to -1 when the block is absent
     * @param seconds native whole epoch seconds, or -1 when not supplied
     * @param time reconstructed decimal epoch-seconds string, or null without source time
     * @param dateParts original component/tag/value triples for provenance
     * @param timezone most recent serialized FF record, retained as opaque text
     * @param header ordered metadata-header names used by indexed-name references
     * @param fields typed indexed values with raw references resolved and multivalues ordered
     * @param meta per-record key/value metadata such as _MetaData:Index
     * @param raw original log-data bytes; the second payload blob in metric records
     */
    public record Event(String host, String source, String sourcetype, String channel, String index,
                        long flags, long stream, long offset, long sequence, long seconds,
                        String time, List<DatePart> dateParts, String timezone, List<String> header,
                        Map<String,Object> fields, Map<String,String> meta, byte[] raw) {
        // Structured records are already one logical event, even with newlines.
        boolean structured() { return (flags & STRUCTURED)!=0; }
        // Empty control records are valid protocol traffic, not empty log events.
        boolean control() { return (flags & TIME_OR_STREAM)==0 && raw.length==0 && fields.isEmpty(); }
    }
    private record Meta(String source,String host,String sourcetype,String channel,List<String> header) {}
    // Deferred references: the field list appears before the blobs it addresses.
    private record Ref(String name,int offset,int length,boolean escaped) {}
    private record Metric(String name,int offset) {}
    private final Limits limits;
    /**
     * Construct a decoder using the input's request resource bounds.
     * @param limits bounds for decoded data records and payload allocations
     */
    public S2SDecoder(Limits limits) { this.limits=limits; }

    /**
     * Decode a complete HTTP entity. Metadata IDs and timezone state are local
     * to this call; another request must supply its own definitions. The shared
     * expansion/memory budgets include any outer HTTP gzip already decoded.
     */
    List<Event> decode(byte[] body, Compression.Expansion expansion, MemoryBudget.Lease memory) {
        byte[] bytes=Compression.zlib(body,expansion);
        Reader r=new Reader(bytes,memory);
        Map<Long,Meta> metas=new HashMap<>(); List<Event> events=new ArrayList<>();
        String timezone=null;
        while (!r.eof()) {
            memory.charge(512);
            // Opcodes use u8(), unlike the varints following them: FF/FE/FC/F8
            // have their high bit set but that bit is NOT a continuation marker.
            switch (r.u8()) {
                case 0xff -> timezone=r.str();
                case 0xfe, 0xf8 -> {
                    // The observed clone-metadata variant has an extra U(1).
                    // Do not treat that marker as the metadata ID or fanout count.
                    if ((bytes[r.pos-1]&255)==0xf8 && r.varint()!=1) throw HecException.invalid();
                    long id=r.varint();
                    String source=strip(r.nstr(),"source::"),host=strip(r.nstr(),"host::"),type=strip(r.nstr(),"sourcetype::");
                    String channel=r.nstr(); int count=r.count(); List<String> header=new ArrayList<>();
                    for(int i=0;i<count;i++) header.add(r.str());
                    // Header indexes used below are zero-based. Redefining an ID
                    // updates subsequent records, not previously returned events.
                    metas.put(id,new Meta(source,host,type,channel,List.copyOf(header)));
                }
                case 0xfc -> {
                    Event e=event(r,metas,timezone,memory);
                    // A trailing control marker is allowed even at the data cap.
                    if (!e.control()) {
                        if (events.size()>=limits.events()) throw HecException.busy();
                        events.add(e);
                    }
                }
                default -> throw HecException.invalid();
            }
        }
        return events;
    }
    /**
     * Decode FC's dependent grammar. Bits 1 and 3 are deliberately tested as a
     * combined mask: either requires stream ID, source offset, sequence AND epoch
     * seconds. Assigning separate guessed meanings would change byte alignment.
     */
    private Event event(Reader r,Map<Long,Meta> metas,String tz,MemoryBudget.Lease memory) {
        return parsedEvent(r,metas,tz,memory,false).event();
    }
    private record Parsed(Event event,Long eventId){}
    private Parsed parsedEvent(Reader r,Map<Long,Meta> metas,String tz,MemoryBudget.Lease memory,boolean tcp) {
        Meta m=metas.get(r.varint()); if(m==null) throw HecException.invalid();
        long flags=r.varint(),stream=0,offset=-1,seq=-1,seconds=-1;
        Long eventId=null;
        if(flags<0||flags>0xffffffffL)throw HecException.invalid();
        if(tcp){
            if((flags&TCP_STREAM_POS)!=0){stream=r.varint();offset=r.varint();seq=r.varint();}
            if((flags&TCP_EVENT_ID)!=0)eventId=r.varint();
            if((flags&TCP_TIMESTAMP)!=0){seconds=r.varint();if(seconds<0)throw HecException.invalid();}
        }else if((flags & TIME_OR_STREAM)!=0) {
            stream=r.varint();offset=r.varint();seq=r.varint();seconds=r.varint();
            if(seconds<0)throw HecException.invalid();
        }
        // fieldCount includes control metadata and date parts, not just the
        // indexed values that eventually appear in the output's fields map.
        int count=r.count(); Map<String,Object> fields=new LinkedHashMap<>();Map<String,String> meta=new LinkedHashMap<>();
        List<DatePart> parts=new ArrayList<>();List<Metric> metrics=new ArrayList<>();
        String fraction="";
        for(int i=0;i<count;i++) {
            memory.charge(512);
            // First decode the WHOLE tag varint, then apply masks to that integer.
            // Example wire B3 03 -> logical 0x1B3: kind 4, inline name, formatting.
            // Dispatch precedence matters: metadata/date tags are not ordinary
            // indexed-value tags even when some low bits look like value kinds.
            int tag=r.length();
            // Exact tag 04 is S(key), S(value); _MetaData:Index supplies the index.
            if(tag==4) meta.put(r.str(),r.str());
            else if(tcp&&tag==TCP_RESENT) {
                // Observed on latest HF TLS streams only for records the sender retransmits
                // after its acknowledgement wait expired: U(marker) S("resent"). Keep it as
                // wire provenance; it is neither an indexed field nor a payload change.
                long marker=r.varint();String text=r.str();
                meta.put("resent",text);meta.put("resent_marker",Long.toUnsignedString(marker));
            }
            else if((tag & 0xc0)==0x40) {
                // Compact TCP date parts are known only as 0x42/0x4a (and their sign variants).
                // Anything else is a new tag layout: fail closed instead of misparsing later bytes.
                if(tcp&&(tag&0xdf)!=0x42&&(tag&0xdf)!=0x4a)throw HecException.invalid();
                // Low-byte bits 7..6 = 01 identify date parts; bit 5 carries a
                // negative sign (for example a zone offset). Preserve raw tags
                // because some variants use shared constants, not calendar units.
                int part=r.length();long value=r.varint();
                if(value<0)throw HecException.invalid();
                parts.add(new DatePart(part,tag,(tag&0x20)!=0?-value:value));
                if(part==0) fraction=fraction(value);
            } else if((tag&1)!=0) {
                // Indexed-value layout: bits 4..2 = kind, bit 1 = inline-name
                // selector, bit 0 = indexed marker. With bit 1 clear the next
                // varint selects a name from the metadata tuple's header list.
                String key=(tag&2)!=0?r.str():header(m,r.length());
                switch((tag>>2)&7) {
                    // Unsigned integers use BigInteger when the long carrier's
                    // sign bit is set; silently returning a negative value loses data.
                    case 0 -> {long n=r.varint();add(fields,key,n<0?new java.math.BigInteger(Long.toUnsignedString(n)):n);}
                    case 1 -> add(fields,key,r.str());
                    // These are observed indexed-extraction constants. ID 60 is
                    // Splunk's indexed literal "null", not a JSON null conversion.
                    case 2 -> { long c=r.varint();add(fields,key,c==62?true:c==61?false:c==60?"null":c); }
                    // Both offsets address the later RAW blob, in UTF-8 bytes.
                    // Kind 6 additionally unescapes the slice as JSON string content.
                    case 3,6 -> add(fields,key,new Ref(key,r.length(),r.length(),((tag>>2)&7)==6));
                    case 4 -> {
                        // Kind 4 points into the METRIC VALUES blob instead.
                        // Attribute bits 7/8 request two extra display varints;
                        // consume them to stay aligned, without changing the value.
                        int at=r.length(); if((tag&0x180)!=0) {r.varint();r.varint();}
                        metrics.add(new Metric(key.startsWith("metric_name:")?key.substring(12):key,at));
                    }
                    default -> throw HecException.invalid();
                }
            } else throw HecException.invalid();
        }
        // Critical exception: a zero-flags/zero-fields marker omits even the
        // raw-length varint. All other records have a first length-prefixed blob.
        byte[] raw=!tcp&&flags==0&&count==0?new byte[0]:r.bytes(r.length());
        if((flags & METRIC)!=0) {
            // Metric layout is B(binary values), B(raw text), not the reverse.
            // A measurement is an IEEE-754 double at the field's byte offset:
            // logical 1.25 = 0x3FF4000000000000; wire 00 00 00 00 00 00 F4 3F.
            byte[] values=raw;raw=r.bytes(r.length());
            ByteBuffer buf=ByteBuffer.wrap(values).order(ByteOrder.LITTLE_ENDIAN);
            for(Metric metric:metrics) {
                if(metric.offset<0||metric.offset>values.length-8) throw HecException.invalid();
                double n=buf.getDouble(metric.offset);if(!Double.isFinite(n)) throw HecException.invalid();
                add(fields,metric.name,n);
            }
        } else if(!metrics.isEmpty()) throw HecException.invalid();
        // Resolve only after selecting the final raw blob. Numeric-looking slices
        // remain text; numeric interpretation is defined by the wire field kind.
        for(var entry:fields.entrySet()) {
            Object v=entry.getValue();
            if(v instanceof Ref ref) entry.setValue(resolve(raw,ref,memory));
            else if(v instanceof List<?> list) {
                List<Object> resolved=new ArrayList<>();
                for(Object item:list) resolved.add(item instanceof Ref ref?resolve(raw,ref,memory):item);
                entry.setValue(resolved);
            }
        }
        // Keep decimal source time without a floating-point/millisecond round trip.
        // The downstream mapper creates the runtime Timestamp separately.
        String time=seconds<0?null:Long.toString(seconds)+(fraction.isEmpty()?"":"."+fraction);
        String host=m.host,source=m.source,sourcetype=m.sourcetype;
        if(tcp){
            // Compact TCP can override channel metadata on a record (for example
            // zero-ID fwdinfo/fwd-hb records). Indexed fields named host are NOT
            // these control keys. The reserved startup host delegates to peer defaults.
            host=strip(meta.getOrDefault("MetaData:Host",host),"host::");
            source=strip(meta.getOrDefault("MetaData:Source",source),"source::");
            sourcetype=strip(meta.getOrDefault("MetaData:Sourcetype",sourcetype),"sourcetype::");
            if("$decideOnStartup".equals(host))host=null;
        }
        return new Parsed(new Event(host,source,sourcetype,m.channel,meta.get("_MetaData:Index"),flags,
            stream,offset,seq,seconds,time,List.copyOf(parts),tz,m.header,fields,meta,raw),eventId);
    }
    /**
     * Subsecond integer encoding: {@code v = (digits << (z+1)) | (1 << z)}, where z is
     * the count of leading decimal zeroes. The least-significant set bit is the
     * marker, not a decimal digit. Examples: 815 -> .407; 63356 -> .007919.
     * Preserve the digits here; the native timestamp validator checks precision.
     */
    static String fraction(long value) {
        if(value<=0) return "";
        int zeroes=Long.numberOfTrailingZeros(value);
        return "0".repeat(zeroes)+Long.toString(value >>> (zeroes+1));
    }
    /** Resolve raw[offset:offset+length], never source-file or HTTP-body offsets. */
    private static String resolve(byte[] raw,Ref ref,MemoryBudget.Lease memory) {
        if(ref.offset<0||ref.length<0||ref.offset>raw.length-ref.length) throw HecException.invalid();
        memory.charge(10L*ref.length+256);
        String s=HecProtocol.utf8(Arrays.copyOfRange(raw,ref.offset,ref.offset+ref.length));
        if(!ref.escaped) return s;
        // Wrap escaped CONTENT in quotes for Jackson; require the entire slice
        // so an unescaped quote cannot make the parser silently discard a suffix.
        try { return HecProtocol.JSON.readerFor(String.class)
            .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .readValue("\""+s+"\""); }
        catch(Exception e) {throw HecException.invalid();}
    }
    // Repeated indexed names represent ordered multivalues, not last-write-wins.
    @SuppressWarnings("unchecked") private static void add(Map<String,Object> fields,String key,Object value) {
        if(!fields.containsKey(key)) fields.put(key,value);
        else if(fields.get(key) instanceof List<?> list) ((List<Object>)list).add(value);
        else { List<Object> l=new ArrayList<>();l.add(fields.get(key));l.add(value);fields.put(key,l); }
    }
    private static String header(Meta m,int index) { if(index>=m.header.size()) throw HecException.invalid(); return m.header.get(index); }
    private static String strip(String value,String prefix) {return value!=null&&value.startsWith(prefix)?value.substring(prefix.length()):value;}

    /**
     * Result of decoding ONE record from a TCP stream.
     * @param event       the decoded event, or null for metadata/timezone/close records
     * @param eventId     the sender's unsigned event/ACK id, or null when the record has none
     * @param wireSha256  SHA-256 over every byte consumed for this record; used only as the fallback
     *                    identity for records without source coordinates
     * @param retainsLease true when the record's memory reservation must be kept (channel metadata and
     *                    timezone stay live for the connection) instead of released after processing
     */
    record StreamRecord(Event event,Long eventId,String wireSha256,boolean retainsLease){}

    /**
     * Per-connection compact TCP dictionary. Typed field decoding is shared with
     * HTTP, but TCP's event-ID bit and conditional header are transport-specific.
     * Metadata/timezone leases are retained until replacement/close; event leases
     * remain owned by the caller until queue acceptance. No growing input buffer
     * or re-decoding of partial packets is needed: reads are exact and bounded.
     */
    final class StreamSession implements AutoCloseable{
        /** Channel id to its (source, host, sourcetype, header) tuple, as defined by FE/F8 records. */
        private final Map<Long,Meta> metas=new HashMap<>();
        /** The memory reservation backing each live channel definition; freed on replace/close. */
        private final Map<Long,MemoryBudget.Lease> leases=new HashMap<>();
        /** Serialized timezone most recently announced by an FF record, attached to later events. */
        private String timezone;
        private MemoryBudget.Lease timezoneLease;
        /**
         * Read the remainder of one record whose first byte (the opcode) the caller already consumed.
         * The reader pulls bytes directly from the stream with exact bounded reads, so a record split
         * across TCP segments simply blocks until the rest arrives (under the caller's deadline); there
         * is never a partially parsed record to resume.
         *
         * <p>Opcodes: {@code FF} timezone text; {@code FE} define/replace a channel; {@code F8} the same
         * with an extra leading U(1) (observed on heavy-forwarder "clone" channels); {@code FD} close a
         * channel; {@code FC} one event. Anything else is a corrupt or unsupported stream.
         */
        StreamRecord read(int opcode,InputStream input,MemoryBudget.Lease memory){
            memory.charge(512);Reader r=new Reader(input,memory,opcode);
            switch(opcode){
                case 0xff -> {
                    // Timezone: kept for later events. Replacing it frees the previous reservation.
                    String next=r.str(),hash=r.hash();
                    if(timezoneLease!=null)timezoneLease.close();
                    timezone=next;timezoneLease=memory;
                    return new StreamRecord(null,null,hash,true);
                }
                case 0xfe,0xf8 -> {
                    // Latest real HF clone records use this observed U(1) prefix
                    // and supply all four slots. Do not invent template inheritance.
                    if(opcode==0xf8&&r.varint()!=1)throw HecException.invalid();
                    long id=r.varint();
                    // Cap NEW channels at the advertised limit; redefining an existing id is always fine.
                    if(!metas.containsKey(id)&&metas.size()>=S2STcpProtocol.CHANNEL_LIMIT)throw HecException.busy();
                    String source=strip(r.nstr(),"source::"),host=strip(r.nstr(),"host::"),type=strip(r.nstr(),"sourcetype::");
                    String channel=r.nstr();int count=r.count();List<String> header=new ArrayList<>();
                    for(int i=0;i<count;i++)header.add(r.str());
                    Meta next=new Meta(source,host,type,channel,List.copyOf(header));String hash=r.hash();
                    // Install the new definition and free the reservation of the one it replaced. The new
                    // record's own lease is retained (retainsLease=true) for the lifetime of the channel.
                    var old=leases.put(id,memory);metas.put(id,next);if(old!=null)old.close();
                    return new StreamRecord(null,null,hash,true);
                }
                case 0xfd -> {
                    // Channel closed by the sender: forget it and release its reservation.
                    long id=r.varint();metas.remove(id);var old=leases.remove(id);if(old!=null)old.close();
                    return new StreamRecord(null,null,r.hash(),false);
                }
                case 0xfc -> {
                    // One event. "true" selects the TCP header layout (independent flag bits) and the
                    // per-record MetaData:* overrides; see parsedEvent.
                    Parsed parsed=parsedEvent(r,metas,timezone,memory,true);
                    return new StreamRecord(parsed.event(),parsed.eventId(),r.hash(),false);
                }
                default -> throw HecException.invalid();
            }
        }
        @Override public void close(){for(var lease:leases.values())lease.close();leases.clear();metas.clear();if(timezoneLease!=null)timezoneLease.close();}
    }
    /** Byte cursor for the inflated body; string boundaries are length-based, not NUL-terminated. */
    private final class Reader {
        final byte[] bytes;final InputStream input;final MessageDigest digest;final MemoryBudget.Lease memory;int pos;
        Reader(byte[] bytes,MemoryBudget.Lease memory){this.bytes=bytes;this.input=null;this.digest=null;this.memory=memory;}
        Reader(InputStream input,MemoryBudget.Lease memory,int opcode){
            this.bytes=null;this.input=input;this.memory=memory;this.pos=1;
            try{digest=MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
            digest.update((byte)opcode);
        }
        String hash(){return HexFormat.of().formatHex(digest.digest());}
        boolean eof(){return pos==bytes.length;}
        int u8(){
            if(input==null){if(pos>=bytes.length)throw HecException.invalid();return bytes[pos++]&255;}
            if(pos>=limits.expanded())throw HecException.busy();
            try{
                int value=input.read();if(value<0)throw new EOFException("truncated TCP record");
                pos++;digest.update((byte)value);return value;
            }catch(IOException error){throw new UncheckedIOException(error);}
        }
        /**
         * Unsigned LEB128-style groups: bit 7 continues; bits 6..0 contribute
         * at shifts 0,7,14,... . {@code AC 02 = 44 + (2 << 7) = 300}. This is not ZigZag.
         * The Java long retains uint64 bits; callers choose unsigned presentation.
         */
        long varint(){
            long value=0;
            // Stream identifiers are uint64 in real senders. Preserve the bits; lengths must be signed-safe.
            for(int shift=0;shift<70;shift+=7){
                // The tenth byte has room for only bit 63: payload 0/1 and no
                // continuation. Reject before Java's shift wrapping could hide overflow.
                int b=u8();if(shift==63&&(b&254)!=0)throw HecException.invalid();
                value|=(long)(b&127)<<shift;if((b&128)==0)return value;
            }
            throw HecException.invalid();
        }
        // Allocation lengths/counts have a narrower domain than uint64 identifiers.
        int length(){long n=varint();if(n<0||n>Integer.MAX_VALUE)throw HecException.invalid();return (int)n;}
        int count(){int n=length();if(n>(input==null?bytes.length:limits.expanded())-pos)throw HecException.invalid();return n;}
        byte[] bytes(int n){
            if(n>(input==null?bytes.length:limits.expanded())-pos)throw HecException.invalid();
            // A UF raw record may contain many logical lines. Apply event cap after framing.
            if(n>limits.expanded())throw HecException.busy();
            if(input!=null){
                memory.charge(3L*n+64);
                try{byte[] out=S2STcpProtocol.exact(input,n);pos+=n;digest.update(out);return out;}
                catch(IOException error){throw new UncheckedIOException(error);}
            }
            memory.charge(n+64L);byte[] out=Arrays.copyOfRange(bytes,pos,pos+n);pos+=n;return out;
        }
        // S("")=00; S("abc")=03 61 62 63. Count UTF-8 bytes, not Java characters.
        String str(){int n=length();memory.charge(4L*n+64);return HecProtocol.utf8(bytes(n));}
        // NS(null)=00; NS("")=01; NS("abc")=04 61 62 63. The +1 makes null distinct.
        String nstr(){int n=length();if(n==0)return null;memory.charge(4L*n+64);return HecProtocol.utf8(bytes(n-1));}
    }
}
