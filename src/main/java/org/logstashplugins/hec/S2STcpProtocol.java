package org.logstashplugins.hec;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/**
 * Transport framing for the classic Splunk "cooked" TCP protocol (what a
 * Universal/Heavy Forwarder speaks with {@code tcpout} to port 9997).
 *
 * <p>Everything here was derived from this project's own captures of the latest
 * real UF/HF talking to a real Splunk indexer (see {@code tests/tcp/}), not from
 * Splunk source code and not from any GPL implementation. This is a different
 * layer from the S2S-over-HTTP framing: HTTP sends one {@code F9}+zlib body per
 * request, TCP is one long-lived connection with this sequence:
 *
 * <ol>
 * <li><b>Greeting</b> (sender to receiver, exactly 400 bytes, NUL padded):
 *     signature[128] = {@code --splunk-cooked-mode-v3--}, hostname[256],
 *     management-port[16]. The receiver sends nothing back yet.</li>
 * <li><b>Capability frame</b> (sender to receiver): a length-prefixed key/value
 *     block such as {@code __s2s_capabilities=ack=1;compression=0}. The receiver
 *     answers with its own control frame ({@link #hello}).</li>
 * <li><b>ForwarderInfo frame</b> (sender to receiver): carries {@code _guid}, the
 *     negotiated {@code v4=1} capability and a few descriptive fields.</li>
 * <li><b>Records</b>: the compact record stream decoded by
 *     {@link S2SDecoder.StreamSession}, optionally wrapped in one continuous
 *     {@code F9} + zlib stream ({@link Inflated}).</li>
 * </ol>
 *
 * <p>Byte-order facts that are easy to get wrong: ordinary handshake frames use
 * big-endian integers. When a sender compresses a handshake frame, the frame is a
 * big-endian length followed by a NUL-terminated finished zlib blob, and the
 * integers INSIDE the inflated key/value block are little-endian. Reverse
 * acknowledgements ({@link #ack}) stay uncompressed in both modes.
 */
final class S2STcpProtocol {
    /** Fixed text every classic cooked-mode connection starts with (padded to 128 bytes). */
    static final String SIGNATURE="--splunk-cooked-mode-v3--";
    /** Maximum number of concurrently open metadata channels we advertise and enforce. */
    static final int CHANNEL_LIMIT=300;
    /** Sender identity from the greeting; both values are self-declared and unauthenticated. */
    record Greeting(String hostname,String managementPort){}
    /** One decoded key/value handshake frame and whether it arrived zlib wrapped. */
    record Frame(Map<String,String> pairs,boolean compressed){}

    /**
     * Read and validate the sender's 400-byte greeting. Each field must be NUL
     * terminated, with nothing but NUL bytes after the terminator, so a malformed
     * or hostile prefix is rejected here instead of being guessed at later.
     */
    static Greeting greeting(InputStream input)throws IOException{
        byte[] bytes=exact(input,400);
        if(!padded(bytes,0,128).equals(SIGNATURE))throw new IOException("unsupported S2S TCP greeting");
        String hostname=padded(bytes,128,256),port=padded(bytes,384,16);
        if(hostname.isEmpty())throw new IOException("empty TCP sender hostname");
        return new Greeting(hostname,port);
    }
    /** Decode one fixed-width, NUL-padded text field and verify that its padding is really only NULs. */
    private static String padded(byte[] bytes,int offset,int length)throws IOException{
        int end=offset;
        while(end<offset+length&&bytes[end]!=0)end++;
        // No terminator at all means the field used its whole width: not a valid greeting.
        if(end==offset+length)throw new IOException("unterminated greeting field");
        for(int p=end;p<offset+length;p++)if(bytes[p]!=0)throw new IOException("nonzero greeting padding");
        return HecProtocol.utf8(Arrays.copyOfRange(bytes,offset,end));
    }
    /**
     * Read one length-prefixed key/value handshake frame.
     *
     * <p>Layout of the (possibly inflated) body: {@code u32 pairCount}, then for
     * every pair two {@code u32 length}+bytes+{@code NUL} strings (key, value),
     * then the trailer {@code u32 0} followed by the string {@code "_raw"}. The
     * trailer is checked so a truncated or shifted frame cannot be mistaken for a
     * valid one. All sizes are bounded and charged to the shared memory budget
     * BEFORE they are allocated, so an untrusted sender cannot make us allocate
     * more than the configured limits.
     */
    static Frame frame(InputStream input,Limits limits,MemoryBudget.Lease memory)throws IOException{
        long length=Integer.toUnsignedLong(new DataInputStream(input).readInt());
        // 17 bytes is the smallest conceivable frame; the upper bound is the wire limit.
        if(length<17||length>limits.wire())throw new IOException("invalid TCP handshake frame size");
        // Reserve room for the raw frame, a possible inflated copy and parsed strings.
        memory.charge(3L*length+1024);
        byte[] body=exact(input,(int)length);boolean compressed=false;
        // A zlib stream starts with CMF/FLG bytes where CMF&15==8 (deflate) and the
        // 16-bit header is divisible by 31. That, plus the wrapper length check below,
        // identifies the compressed wrapper without trusting the capability string.
        if(body.length>=7&&(body[4]&15)==8&&(((body[4]&255)<<8)|(body[5]&255))%31==0){
            int count=ByteBuffer.wrap(body).getInt();
            if(count!=body.length-4||body[body.length-1]!=0)throw new IOException("invalid compressed handshake wrapper");
            body=inflateFrame(body,limits,memory);compressed=true;
        }
        try{
            // Observed: inflated blocks are little-endian, plain blocks big-endian.
            ByteBuffer b=ByteBuffer.wrap(body).order(compressed?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
            long pairs=Integer.toUnsignedLong(b.getInt());
            // Every pair needs at least 8 bytes of length prefixes, so a larger count is impossible.
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
    /** Read one {@code u32 length} + bytes (+ trailing NUL) string out of a handshake block. */
    private static String string(ByteBuffer b,MemoryBudget.Lease memory)throws IOException{
        long length=Integer.toUnsignedLong(b.getInt());
        // The stored length includes the terminating NUL, so at least 1 and never beyond the buffer.
        if(length<1||length>b.remaining())throw new IOException("invalid TCP string length");
        memory.charge(5L*length+128);
        byte[] bytes=new byte[(int)length];b.get(bytes);
        if(bytes[bytes.length-1]!=0)throw new IOException("missing TCP string terminator");
        int end=bytes.length;while(end>0&&bytes[end-1]==0)end--;
        return HecProtocol.utf8(Arrays.copyOf(bytes,end));
    }
    /**
     * Inflate a compressed handshake frame. The wrapper is {@code u32 length +
     * zlib + NUL}; the trailing NUL belongs to the wrapper, not to the zlib data,
     * so it is excluded. Output size is capped by the expansion limit and charged
     * to the memory budget as it grows, which defeats decompression bombs.
     */
    private static byte[] inflateFrame(byte[] wrapped,Limits limits,MemoryBudget.Lease memory)throws IOException{
        Inflater inflater=new Inflater();
        try{
            inflater.setInput(wrapped,4,wrapped.length-5); // skip the length prefix and the final NUL
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
    /**
     * Test a boolean capability inside a {@code name=value;name=value} string,
     * for example {@code capability("ack=1;compression=0","ack")} is true. A
     * missing key is false; only "1" and "true" count as set.
     */
    static boolean capability(String text,String name){
        if(text==null)return false;
        for(String item:text.split(";")){
            int at=item.indexOf('=');
            if(at>0&&item.substring(0,at).equals(name))return Set.of("1","true").contains(item.substring(at+1));
        }
        return false;
    }
    /**
     * The receiver's answer to the sender's capability frame. We advertise ONLY
     * what is implemented: the compact v4 record format and a channel limit.
     * Heartbeats, token exchange and certificate requests are explicitly off, and
     * acknowledgements are decided by the sender's own {@code ack=1} request.
     */
    static void hello(OutputStream output)throws IOException{
        writeFrame(output,Map.of("__s2s_control_msg","cap_response=success;cap_flush_key=true;idx_can_send_hb=false;idx_can_recv_token=false;request_certificate=false;v4=true;channel_limit=300;pl=7"));
    }
    /** Serialize a plain (uncompressed, big-endian) key/value frame in the format {@link #frame} reads. */
    static void writeFrame(OutputStream output,Map<String,String> pairs)throws IOException{
        ByteArrayOutputStream body=new ByteArrayOutputStream();DataOutputStream b=new DataOutputStream(body);
        b.writeInt(pairs.size());
        for(var entry:pairs.entrySet()){writeString(b,entry.getKey());writeString(b,entry.getValue());}
        b.writeInt(0);writeString(b,"_raw");
        DataOutputStream wire=new DataOutputStream(output);wire.writeInt(body.size());body.writeTo(wire);wire.flush();
    }
    /** Write {@code u32 (length+1)}, the UTF-8 bytes, and the terminating NUL. */
    private static void writeString(DataOutputStream output,String value)throws IOException{
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);output.writeInt(bytes.length+1);output.write(bytes);output.writeByte(0);
    }
    /**
     * Acknowledge one event ID: {@code FB} + unsigned varint. The real receiver
     * also has {@code FA lo hi}, an inclusive range form; single IDs are enough
     * and cannot accidentally acknowledge a gap. Flushed immediately because the
     * sender is waiting on it. Callers must only ack AFTER the queue accepted the
     * record's events, which is the delivery guarantee this plugin documents.
     */
    static void ack(OutputStream output,long eventId)throws IOException{
        output.write(0xfb);unsigned(output,eventId);output.flush();
    }
    /** Little-endian base-128 varint of the raw 64 bits (IDs are unsigned, so no sign handling). */
    static void unsigned(OutputStream output,long bits)throws IOException{
        while((bits&~127L)!=0){output.write((int)(bits&127)|128);bits>>>=7;}output.write((int)bits);
    }
    /** Read exactly {@code n} bytes or fail; a short read means the peer closed mid-frame. */
    static byte[] exact(InputStream input,int n)throws IOException{
        byte[] bytes=input.readNBytes(n);
        if(bytes.length!=n)throw new EOFException("truncated S2S TCP framing");
        return bytes;
    }

    /**
     * Presents the inbound record stream after the compact marker {@code F9} as
     * plain bytes: ONE continuous zlib stream for the whole connection (not one
     * per record), which forwarders "sync flush" after each batch instead of
     * finishing it.
     *
     * <p>Because the stream is never finished, EOF needs care. A clean sender
     * disconnect leaves the last flush marker {@code 00 00 FF FF} as the final four
     * bytes; that is accepted as end of stream. Any other EOF is a truncation and
     * raises an exception. Even a clean EOF in the middle of a logical record is
     * caught later by the record reader, so a half record is never inserted or ACKed.
     */
    static final class Inflated extends InputStream{
        private final InputStream source;
        private final Inflater inflater=new Inflater();
        private final byte[] compressed=new byte[8192],single=new byte[1];
        /** Rolling last four compressed bytes, compared with the sync-flush marker at EOF. */
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
                        // A finished zlib stream must not be followed by more bytes.
                        if(inflater.getRemaining()!=0)throw new IOException("trailing S2S compressed bytes");
                        eof=true;return -1;
                    }
                    if(inflater.needsDictionary())throw new IOException("unsupported S2S dictionary");
                    if(!inflater.needsInput())throw new IOException("S2S inflater made no progress");
                    // The inflater has consumed everything it was given: fetch more compressed bytes.
                    int count=source.read(compressed);
                    if(count<0){
                        // Orderly close: only accepted when the stream ended on a sync-flush boundary.
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
