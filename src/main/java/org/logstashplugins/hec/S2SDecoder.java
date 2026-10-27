/*
 * Wire decoder ported from mingshsg/elastic-ingest-splunk-forwarders,
 * revision 1280a8e16a30a979d9dde1ff0328ee7d32b0ce99 (Apache-2.0).
 * MODIFIED: standalone Java, strict UTF-8/references/varints, complete-batch rejection,
 * bounded allocations, no salvage, no Elasticsearch dependencies or time truncation.
 */
package org.logstashplugins.hec;

import java.math.BigDecimal;
import java.nio.*;
import java.util.*;

public final class S2SDecoder {
    static final int STRUCTURED=0x40, TIME_OR_STREAM=0x0a, METRIC=0x10000;
    public record DatePart(int part, int tag, long value) {}
    public record Event(String host, String source, String sourcetype, String channel, String index,
                        long flags, long stream, long offset, long sequence, long seconds,
                        String time, List<DatePart> dateParts, String timezone, List<String> header,
                        Map<String,Object> fields, Map<String,String> meta, byte[] raw) {
        boolean structured() { return (flags & STRUCTURED)!=0; }
        boolean control() { return (flags & TIME_OR_STREAM)==0 && raw.length==0 && fields.isEmpty(); }
    }
    private record Meta(String source,String host,String sourcetype,String channel,List<String> header) {}
    private record Ref(String name,int offset,int length,boolean escaped) {}
    private record Metric(String name,int offset) {}
    private final Limits limits;
    public S2SDecoder(Limits limits) { this.limits=limits; }

    List<Event> decode(byte[] body, Compression.Expansion expansion, MemoryBudget.Lease memory) {
        byte[] bytes=Compression.zlib(body,expansion);
        Reader r=new Reader(bytes,memory);
        Map<Long,Meta> metas=new HashMap<>(); List<Event> events=new ArrayList<>();
        String timezone=null;
        while (!r.eof()) {
            memory.charge(512);
            switch (r.u8()) {
                case 0xff -> timezone=r.str();
                case 0xfe, 0xf8 -> {
                    if ((bytes[r.pos-1]&255)==0xf8 && r.varint()!=1) throw HecException.invalid();
                    long id=r.varint();
                    String source=strip(r.nstr(),"source::"),host=strip(r.nstr(),"host::"),type=strip(r.nstr(),"sourcetype::");
                    String channel=r.nstr(); int count=r.count(); List<String> header=new ArrayList<>();
                    for(int i=0;i<count;i++) header.add(r.str());
                    metas.put(id,new Meta(source,host,type,channel,List.copyOf(header)));
                }
                case 0xfc -> {
                    Event e=event(r,metas,timezone,memory);
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
    private Event event(Reader r,Map<Long,Meta> metas,String tz,MemoryBudget.Lease memory) {
        Meta m=metas.get(r.varint()); if(m==null) throw HecException.invalid();
        long flags=r.varint(),stream=0,offset=-1,seq=-1,seconds=-1;
        if(flags<0||flags>0xffffffffL)throw HecException.invalid();
        if((flags & TIME_OR_STREAM)!=0) {
            stream=r.varint();offset=r.varint();seq=r.varint();seconds=r.varint();
            if(seconds<0)throw HecException.invalid();
        }
        int count=r.count(); Map<String,Object> fields=new LinkedHashMap<>();Map<String,String> meta=new LinkedHashMap<>();
        List<DatePart> parts=new ArrayList<>();List<Metric> metrics=new ArrayList<>();
        String fraction="";
        for(int i=0;i<count;i++) {
            memory.charge(512);
            int tag=r.length();
            if(tag==4) meta.put(r.str(),r.str());
            else if((tag & 0xc0)==0x40) {
                int part=r.length();long value=r.varint();
                if(value<0)throw HecException.invalid();
                parts.add(new DatePart(part,tag,(tag&0x20)!=0?-value:value));
                if(part==0) fraction=fraction(value);
            } else if((tag&1)!=0) {
                String key=(tag&2)!=0?r.str():header(m,r.length());
                switch((tag>>2)&7) {
                    case 0 -> {long n=r.varint();add(fields,key,n<0?new java.math.BigInteger(Long.toUnsignedString(n)):n);}
                    case 1 -> add(fields,key,r.str());
                    case 2 -> { long c=r.varint();add(fields,key,c==62?true:c==61?false:c==60?"null":c); }
                    case 3,6 -> add(fields,key,new Ref(key,r.length(),r.length(),((tag>>2)&7)==6));
                    case 4 -> {
                        int at=r.length(); if((tag&0x180)!=0) {r.varint();r.varint();}
                        metrics.add(new Metric(key.startsWith("metric_name:")?key.substring(12):key,at));
                    }
                    default -> throw HecException.invalid();
                }
            } else throw HecException.invalid();
        }
        byte[] raw=flags==0&&count==0?new byte[0]:r.bytes(r.length());
        if((flags & METRIC)!=0) {
            byte[] values=raw;raw=r.bytes(r.length());
            ByteBuffer buf=ByteBuffer.wrap(values).order(ByteOrder.LITTLE_ENDIAN);
            for(Metric metric:metrics) {
                if(metric.offset<0||metric.offset>values.length-8) throw HecException.invalid();
                double n=buf.getDouble(metric.offset);if(!Double.isFinite(n)) throw HecException.invalid();
                add(fields,metric.name,n);
            }
        } else if(!metrics.isEmpty()) throw HecException.invalid();
        for(var entry:fields.entrySet()) {
            Object v=entry.getValue();
            if(v instanceof Ref ref) entry.setValue(resolve(raw,ref,memory));
            else if(v instanceof List<?> list) {
                List<Object> resolved=new ArrayList<>();
                for(Object item:list) resolved.add(item instanceof Ref ref?resolve(raw,ref,memory):item);
                entry.setValue(resolved);
            }
        }
        String time=seconds<0?null:Long.toString(seconds)+(fraction.isEmpty()?"":"."+fraction);
        return new Event(m.host,m.source,m.sourcetype,m.channel,meta.get("_MetaData:Index"),flags,
            stream,offset,seq,seconds,time,List.copyOf(parts),tz,m.header,fields,meta,raw);
    }
    static String fraction(long value) {
        if(value<=0) return "";
        int zeroes=Long.numberOfTrailingZeros(value);
        return "0".repeat(zeroes)+Long.toString(value >>> (zeroes+1));
    }
    private static String resolve(byte[] raw,Ref ref,MemoryBudget.Lease memory) {
        if(ref.offset<0||ref.length<0||ref.offset>raw.length-ref.length) throw HecException.invalid();
        memory.charge(10L*ref.length+256);
        String s=HecProtocol.utf8(Arrays.copyOfRange(raw,ref.offset,ref.offset+ref.length));
        if(!ref.escaped) return s;
        try { return HecProtocol.JSON.readerFor(String.class)
            .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .readValue("\""+s+"\""); }
        catch(Exception e) {throw HecException.invalid();}
    }
    @SuppressWarnings("unchecked") private static void add(Map<String,Object> fields,String key,Object value) {
        if(!fields.containsKey(key)) fields.put(key,value);
        else if(fields.get(key) instanceof List<?> list) ((List<Object>)list).add(value);
        else { List<Object> l=new ArrayList<>();l.add(fields.get(key));l.add(value);fields.put(key,l); }
    }
    private static String header(Meta m,int index) { if(index>=m.header.size()) throw HecException.invalid(); return m.header.get(index); }
    private static String strip(String value,String prefix) {return value!=null&&value.startsWith(prefix)?value.substring(prefix.length()):value;}
    private final class Reader {
        final byte[] bytes;final MemoryBudget.Lease memory;int pos;
        Reader(byte[] bytes,MemoryBudget.Lease memory){this.bytes=bytes;this.memory=memory;}
        boolean eof(){return pos==bytes.length;}
        int u8(){if(pos>=bytes.length) throw HecException.invalid();return bytes[pos++]&255;}
        long varint(){
            long value=0;
            // Stream identifiers are uint64 in real senders. Preserve the bits; lengths must be signed-safe.
            for(int shift=0;shift<70;shift+=7){
                int b=u8();if(shift==63&&(b&254)!=0)throw HecException.invalid();
                value|=(long)(b&127)<<shift;if((b&128)==0)return value;
            }
            throw HecException.invalid();
        }
        int length(){long n=varint();if(n<0||n>Integer.MAX_VALUE)throw HecException.invalid();return (int)n;}
        int count(){int n=length();if(n>bytes.length-pos)throw HecException.invalid();return n;}
        byte[] bytes(int n){
            if(n>bytes.length-pos)throw HecException.invalid();
            // A UF raw record may contain many logical lines. Apply event cap after framing.
            if(n>limits.expanded())throw HecException.busy();
            memory.charge(n+64L);byte[] out=Arrays.copyOfRange(bytes,pos,pos+n);pos+=n;return out;
        }
        String str(){int n=length();memory.charge(4L*n+64);return HecProtocol.utf8(bytes(n));}
        String nstr(){int n=length();if(n==0)return null;memory.charge(4L*n+64);return HecProtocol.utf8(bytes(n-1));}
    }
}
