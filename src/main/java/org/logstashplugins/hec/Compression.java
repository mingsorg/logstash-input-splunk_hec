package org.logstashplugins.hec;

import java.io.ByteArrayOutputStream;
import java.util.zip.*;

final class Compression {
    static final class Expansion {
        private final long max;
        private long expanded;
        private final MemoryBudget.Lease memory;
        Expansion(long max, MemoryBudget.Lease memory) { this.max = max; this.memory = memory; }
        void allocate(int n) {
            if (n < 0 || n > max-expanded) throw HecException.busy();
            memory.charge(3L*n); expanded += n; // output + growth copy + final copy
        }
    }
    static byte[] zlib(byte[] input, Expansion budget) {
        if (input.length == 0) return input;
        if ((input[0] & 255) != 0xf9 || input.length < 3) throw HecException.invalid();
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(input, 1, input.length-1);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            pump(inflater, out, budget);
            if (inflater.needsDictionary() || inflater.getRemaining() != 0) throw HecException.invalid();
            if (!inflater.finished()) {
                int n = input.length;
                if (!inflater.needsInput() || n < 5 || input[n-4]!=0 || input[n-3]!=0 ||
                    (input[n-2]&255)!=255 || (input[n-1]&255)!=255) throw HecException.invalid();
            }
            return out.toByteArray();
        } catch (DataFormatException e) { throw HecException.invalid(); }
        finally { inflater.end(); }
    }
    static byte[] gzip(byte[] input, Expansion budget) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        int at = 0;
        do {
            int start = at;
            if (input.length-at < 10 || u8(input,at++)!=31 || u8(input,at++)!=139 || u8(input,at++)!=8) throw HecException.invalid();
            int flags = u8(input,at++);
            if ((flags & 224)!=0) throw HecException.invalid();
            at += 6;
            if ((flags&4)!=0) {
                int len = u8(input,at) | u8(input,at+1)<<8; at += 2;
                if (len > input.length-at) throw HecException.invalid(); at += len;
            }
            if ((flags&8)!=0) while (u8(input,at++)!=0) { /* bounded by u8 */ }
            if ((flags&16)!=0) while (u8(input,at++)!=0) { /* bounded by u8 */ }
            if ((flags&2)!=0) {
                CRC32 h = new CRC32(); h.update(input,start,at-start);
                int expected = u8(input,at) | u8(input,at+1)<<8; at += 2;
                if ((h.getValue()&65535)!=expected) throw HecException.invalid();
            }
            Inflater inf = new Inflater(true);
            try {
                inf.setInput(input,at,input.length-at);
                ByteArrayOutputStream member = new ByteArrayOutputStream();
                pump(inf,member,budget);
                if (!inf.finished()) throw HecException.invalid();
                at = input.length - inf.getRemaining();
                long crc = le32(input,at), size = le32(input,at+4); at += 8;
                byte[] decoded = member.toByteArray();
                CRC32 actual = new CRC32(); actual.update(decoded);
                if (crc!=actual.getValue() || size!=decoded.length) throw HecException.invalid();
                budget.memory.charge(3L*decoded.length);
                all.writeBytes(decoded);
            } catch (DataFormatException e) { throw HecException.invalid(); }
            finally { inf.end(); }
        } while (at < input.length);
        return all.toByteArray();
    }
    private static void pump(Inflater inf, ByteArrayOutputStream out, Expansion budget) throws DataFormatException {
        budget.memory.charge(8192);
        byte[] scratch = new byte[8192];
        while (!inf.finished()) {
            int n = inf.inflate(scratch);
            if (n > 0) { budget.allocate(n); out.write(scratch,0,n); }
            else if (inf.finished()) break;
            else if (inf.needsDictionary()) throw HecException.invalid();
            else if (inf.needsInput()) break;
            else throw HecException.invalid();
        }
    }
    private static int u8(byte[] b,int p) { if (p<0 || p>=b.length) throw HecException.invalid(); return b[p]&255; }
    private static long le32(byte[] b,int p) {
        return (long)u8(b,p) | (long)u8(b,p+1)<<8 | (long)u8(b,p+2)<<16 | (long)u8(b,p+3)<<24;
    }
}
