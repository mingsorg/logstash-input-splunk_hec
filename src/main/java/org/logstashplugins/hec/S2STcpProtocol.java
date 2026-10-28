package org.logstashplugins.hec;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/**
 * TCP transport framing verified against our latest real UF/HF captures.
 * This is separate from HTTP's F9-per-request framing:
 * <ol>
 * <li>400-byte NUL-padded greeting: signature[128], hostname[256], port[16].</li>
 * <li>BE-u32-length capability and ForwarderInfo frames.</li>
 * <li>Negotiated compact records, optionally one continuous F9/zlib stream.</li>
 * </ol>
 * Compressed handshake frames contain a length-prefixed, NUL-terminated finished
 * zlib blob. Its inflated KV integers are little endian in the observed profile;
 * plain handshake KV integers are big endian. Reverse ACK bytes remain plain in
 * BOTH captured compression modes. No Splunk source or GPL implementation is used.
 */
final class S2STcpProtocol {
    static final String SIGNATURE="--splunk-cooked-mode-v3--";
    static final int CHANNEL_LIMIT=300;
    record Greeting(String hostname,String managementPort){}
    record Frame(Map<String,String> pairs,boolean compressed){}

    static Greeting greeting(InputStream input)throws IOException{
        byte[] bytes=exact(input,400);
        if(!padded(bytes,0,128).equals(SIGNATURE))throw new IOException("unsupported S2S TCP greeting");
        String hostname=padded(bytes,128,256),port=padded(bytes,384,16);
        if(hostname.isEmpty())throw new IOException("empty TCP sender hostname");
        return new Greeting(hostname,port);
    }
    private static String padded(byte[] bytes,int offset,int length)throws IOException{
        int end=offset;
        while(end<offset+length&&bytes[end]!=0)end++;
        if(end==offset+length)throw new IOException("unterminated greeting field");
        for(int p=end;p<offset+length;p++)if(bytes[p]!=0)throw new IOException("nonzero greeting padding");
        return HecProtocol.utf8(Arrays.copyOfRange(bytes,offset,end));
    }
    static Frame frame(InputStream input,Limits limits,MemoryBudget.Lease memory)throws IOException{
        long length=Integer.toUnsignedLong(new DataInputStream(input).readInt());
        if(length<17||length>limits.wire())throw new IOException("invalid TCP handshake frame size");
        memory.charge(3L*length+1024);
        byte[] body=exact(input,(int)length);boolean compressed=false;
        if(body.length>=7&&(body[4]&15)==8&&(((body[4]&255)<<8)|(body[5]&255))%31==0){
            int count=ByteBuffer.wrap(body).getInt();
            if(count!=body.length-4||body[body.length-1]!=0)throw new IOException("invalid compressed handshake wrapper");
            body=inflateFrame(body,limits,memory);compressed=true;
        }
        try{
            ByteBuffer b=ByteBuffer.wrap(body).order(compressed?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
            long pairs=Integer.toUnsignedLong(b.getInt());
            if(pairs>body.length/8)throw new IOException("invalid TCP pair count");
            Map<String,String> values=new LinkedHashMap<>();
            for(long i=0;i<pairs;i++){
                String key=string(b,memory),value=string(b,memory);
                if(key.isEmpty()||values.putIfAbsent(key,value)!=null)throw new IOException("invalid duplicate TCP key");
            }
            if(b.getInt()!=0||!string(b,memory).equals("_raw")||b.hasRemaining())throw new IOException("invalid TCP KV trailer");
            return new Frame(Map.copyOf(values),compressed);
        }catch(BufferUnderflowException error){throw new IOException("truncated TCP KV frame",error);}
    }
    private static String string(ByteBuffer b,MemoryBudget.Lease memory)throws IOException{
        long length=Integer.toUnsignedLong(b.getInt());
        if(length<1||length>b.remaining())throw new IOException("invalid TCP string length");
        memory.charge(5L*length+128);
        byte[] bytes=new byte[(int)length];b.get(bytes);
        if(bytes[bytes.length-1]!=0)throw new IOException("missing TCP string terminator");
        int end=bytes.length;while(end>0&&bytes[end-1]==0)end--;
        return HecProtocol.utf8(Arrays.copyOf(bytes,end));
    }
    private static byte[] inflateFrame(byte[] wrapped,Limits limits,MemoryBudget.Lease memory)throws IOException{
        Inflater inflater=new Inflater();
        try{
            inflater.setInput(wrapped,4,wrapped.length-5); // final NUL belongs to the wrapper, not zlib
            ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] scratch=new byte[8192];memory.charge(8192);
            while(!inflater.finished()){
                int n=inflater.inflate(scratch);
                if(n>0){
                    if(n>limits.expanded()-output.size())throw HecException.busy();
                    memory.charge(3L*n);output.write(scratch,0,n);
                }else if(!inflater.finished())throw new IOException("incomplete/dictionary TCP handshake zlib");
            }
            if(inflater.getRemaining()!=0)throw new IOException("trailing compressed handshake bytes");
            return output.toByteArray();
        }catch(DataFormatException error){throw new IOException("invalid handshake zlib",error);}
        finally{inflater.end();}
    }
    static boolean capability(String text,String name){
        if(text==null)return false;
        for(String item:text.split(";")){
            int at=item.indexOf('=');
            if(at>0&&item.substring(0,at).equals(name))return Set.of("1","true").contains(item.substring(at+1));
        }
        return false;
    }
    static void hello(OutputStream output)throws IOException{
        // Advertise only facilities actually implemented. Client-requested ACKs
        // are emitted after queue acceptance; no server heartbeat/token exchange.
        writeFrame(output,Map.of("__s2s_control_msg","cap_response=success;cap_flush_key=true;idx_can_send_hb=false;idx_can_recv_token=false;request_certificate=false;v4=true;channel_limit=300;pl=7"));
    }
    static void writeFrame(OutputStream output,Map<String,String> pairs)throws IOException{
        ByteArrayOutputStream body=new ByteArrayOutputStream();DataOutputStream b=new DataOutputStream(body);
        b.writeInt(pairs.size());
        for(var entry:pairs.entrySet()){writeString(b,entry.getKey());writeString(b,entry.getValue());}
        b.writeInt(0);writeString(b,"_raw");
        DataOutputStream wire=new DataOutputStream(output);wire.writeInt(body.size());body.writeTo(wire);wire.flush();
    }
    private static void writeString(DataOutputStream output,String value)throws IOException{
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);output.writeInt(bytes.length+1);output.write(bytes);output.writeByte(0);
    }
    static void ack(OutputStream output,long eventId)throws IOException{
        // FB + U(id) is the real receiver's single-ID ACK. FA is its inclusive
        // range optimization; singles are sufficient and avoid acknowledging gaps.
        output.write(0xfb);unsigned(output,eventId);output.flush();
    }
    static void unsigned(OutputStream output,long bits)throws IOException{
        while((bits&~127L)!=0){output.write((int)(bits&127)|128);bits>>>=7;}output.write((int)bits);
    }
    static byte[] exact(InputStream input,int n)throws IOException{
        byte[] bytes=input.readNBytes(n);
        if(bytes.length!=n)throw new EOFException("truncated S2S TCP framing");
        return bytes;
    }

    /**
     * Continuous inbound zlib after compact marker F9. Native forwarders flush
     * without finishing, including on orderly EOF. Only an exhausted-input EOF
     * with the recorded empty-stored-block suffix is accepted; an EOF encountered
     * inside a logical record still fails the record reader and receives no ACK.
     */
    static final class Inflated extends InputStream{
        private final InputStream source;
        private final Inflater inflater=new Inflater();
        private final byte[] compressed=new byte[8192],single=new byte[1];
        private int suffix,seen;
        private boolean eof,closed;
        Inflated(InputStream source){this.source=source;}
        @Override public int read()throws IOException{return read(single,0,1)<0?-1:single[0]&255;}
        @Override public int read(byte[] target,int offset,int length)throws IOException{
            Objects.checkFromIndexSize(offset,length,target.length);if(length==0)return 0;if(eof)return -1;
            try{
                for(;;){
                    int n=inflater.inflate(target,offset,length);
                    if(n>0)return n;
                    if(inflater.finished()){
                        if(inflater.getRemaining()!=0)throw new IOException("trailing S2S compressed bytes");
                        eof=true;return -1;
                    }
                    if(inflater.needsDictionary())throw new IOException("unsupported S2S dictionary");
                    if(!inflater.needsInput())throw new IOException("S2S inflater made no progress");
                    int count=source.read(compressed);
                    if(count<0){
                        if(seen>=4&&suffix==0x0000ffff){eof=true;return -1;}
                        throw new EOFException("truncated S2S compressed stream");
                    }
                    if(count==0)throw new IOException("S2S compressed input made no progress");
                    for(int i=0;i<count;i++){suffix=(suffix<<8)|(compressed[i]&255);if(seen<4)seen++;}
                    inflater.setInput(compressed,0,count);
                }
            }catch(DataFormatException error){throw new IOException("invalid S2S stream compression",error);}
        }
        @Override public void close()throws IOException{if(!closed){closed=true;inflater.end();source.close();}}
    }
}
