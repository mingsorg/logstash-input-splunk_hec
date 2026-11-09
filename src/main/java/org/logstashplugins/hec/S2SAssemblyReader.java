package org.logstashplugins.hec;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Pure storage grammar. No paths, locks, recovery actions, policy or publication. */
final class S2SAssemblyReader {
    static final int HEADER=88, MAGIC=0x53325333;
    static final long HISTORY=2*S2SAssemblyStore.SAFETY_MAXIMUM+4096;
    static final long PHYSICAL=8*S2SAssemblyStore.SAFETY_MAXIMUM+32768;
    static final byte[] REFUSAL="S2S assembly migrated to v3; restore backup-v2 to downgrade\n".getBytes(StandardCharsets.US_ASCII);
    static final byte[] FRESH_REFUSAL="S2S assembly v3; downgrade requires explicit state recovery\n".getBytes(StandardCharsets.US_ASCII);
    record Replay(S2SStreamAssembler.State state,long sequence,long prefix,long transactions) {}

    static byte[] checked(byte[] bytes)throws IOException{
        if(bytes.length<65||bytes[64]!='\n')throw new IOException("corrupt assembly snapshot");
        byte[] payload=Arrays.copyOfRange(bytes,65,bytes.length);
        if(!TokenStore.fingerprint(payload).equals(new String(bytes,0,64,StandardCharsets.US_ASCII)))throw new IOException("assembly checksum mismatch");
        return payload;
    }
    static S2SAssemblyStore.Pointer pointer(byte[] payload,ObjectMapper mapper)throws IOException{
        var pointer=mapper.readValue(payload,S2SAssemblyStore.Pointer.class);
        if(pointer.generation()<1||pointer.sequence()<0||pointer.snapshot()==null||!pointer.snapshot().matches("[a-f0-9]{64}"))throw new IOException("invalid assembly generation pointer");
        return pointer;
    }
    static S2SAssemblyStore.Snapshot snapshot(byte[] payload,S2SAssemblyStore.Pointer pointer,ObjectMapper mapper)throws IOException{
        if(!TokenStore.fingerprint(payload).equals(pointer.snapshot()))throw new IOException("assembly generation mismatch");
        var snapshot=mapper.readValue(payload,S2SAssemblyStore.Snapshot.class);
        if(snapshot.sequence()!=pointer.sequence())throw new IOException("assembly snapshot sequence mismatch");
        return snapshot;
    }
    /** Stops only at a short header or an authenticated short payload. Complete errors never fall back. */
    static Replay replay(FileChannel file,S2SStreamAssembler.State initial,long sequence,ObjectMapper mapper,
                         S2SAssemblyStore.Validator validator,long recordLimit)throws IOException{
        long position=0,total=size(file),records=0;var current=initial;validator.validate(current);
        try{
            while(position<total){
                if(total-position<HEADER)break;
                byte[] header=new byte[HEADER];read(file,position,header);var framing=ByteBuffer.wrap(header);
                int magic=framing.getInt(),version=framing.getInt();long ordinal=framing.getLong(),length=framing.getLong();
                if(magic!=MAGIC||version!=3||sequence==Long.MAX_VALUE||ordinal!=sequence+1||length<0||length>HISTORY-HEADER||
                    !Arrays.equals(Arrays.copyOfRange(header,24,56),digest(Arrays.copyOfRange(header,0,24))))throw new IOException("corrupt assembly transaction framing/sequence");
                if(total-position-HEADER<length)break;
                if(++records>recordLimit)throw new BudgetException();
                byte[] payload=new byte[(int)length];read(file,position+HEADER,payload);
                if(!Arrays.equals(Arrays.copyOfRange(header,56,88),digest(payload)))throw new IOException("assembly transaction checksum mismatch");
                var transaction=mapper.readValue(payload,S2SAssemblyStore.Transaction.class);
                current=apply(current,transaction);validator.validate(current);
                sequence=ordinal;position+=HEADER+length;
            }
        }catch(RuntimeException error){throw new IOException("invalid assembly transaction",error);}
        return new Replay(current,sequence,position,records);
    }
    static final class BudgetException extends IOException {
        BudgetException(){super("assembly inspection budget exceeded");}
    }
    static final class ReadFailure extends IOException {
        ReadFailure(IOException cause){super("assembly storage read failed",cause);}
    }
    static long size(FileChannel channel)throws IOException{
        try{return channel.size();}catch(IOException error){throw new ReadFailure(error);}
    }
    static void read(FileChannel channel,long position,byte[] bytes)throws IOException{
        var buffer=ByteBuffer.wrap(bytes);
        try{while(buffer.hasRemaining()){int n=channel.read(buffer,position+buffer.position());if(n<=0)throw new EOFException();}}
        catch(IOException error){throw new ReadFailure(error);}
    }
    static byte[] digest(byte[] bytes){return java.util.HexFormat.of().parseHex(TokenStore.fingerprint(bytes));}

    static S2SStreamAssembler.State apply(S2SStreamAssembler.State old,S2SAssemblyStore.Transaction transaction)throws IOException{
        if(!old.configuration().equals(transaction.configuration()))throw new IOException("assembly transaction configuration mismatch");
        var pending=new LinkedHashMap<>(old.pending());var outbox=new ArrayList<>(old.outbox());var receipts=new LinkedHashMap<>(old.receipts());
        var touched=new HashSet<String>();
        for(String key:transaction.removePending())if(!touched.add(key)||pending.remove(key)==null)throw new IOException("invalid pending removal");
        for(var change:transaction.pending()){
            if(!touched.add(change.key()))throw new IOException("duplicate pending operation");
            var value=change.value();
            if(change.prior()!=null){
                var before=pending.get(change.key());
                if(before==null||!before.chain().equals(change.prior())||value.text().length()!=0||!value.contributions().isEmpty()||
                    value.envelope()!=null||!before.rule().equals(value.rule())||!before.origin().equals(value.origin())||!before.attributes().equals(value.attributes())||
                    before.timeout()!=value.timeout()||before.eventLimit()!=value.eventLimit()||!Objects.equals(before.sender(),value.sender()))throw new IOException("invalid pending append");
                value=new S2SStreamAssembler.Pending(before.envelope(),new AssemblyChunks.Text(before.text(),change.text()),value.delimiter(),value.rule(),value.chain(),value.attributes(),value.origin(),
                    new AssemblyChunks.Contributions(before.contributions(),change.contributions()),value.touched(),value.timeout(),value.offset(),value.sequence(),value.eventLimit(),value.sender());
            }else if(change.text()!=null||change.contributions()!=null)throw new IOException("invalid pending replacement");
            pending.put(change.key(),value);
        }
        if(transaction.pendingOrder()!=null){
            if(transaction.pendingOrder().size()!=pending.size()||!new HashSet<>(transaction.pendingOrder()).equals(pending.keySet()))throw new IOException("invalid pending order");
            var ordered=new LinkedHashMap<String,S2SStreamAssembler.Pending>();for(String key:transaction.pendingOrder())ordered.put(key,pending.get(key));pending=ordered;
        }
        touched.clear();for(String id:transaction.removeOutputs()){if(!touched.add(id)||!outbox.removeIf(output->output.id().equals(id)))throw new IOException("invalid output removal");}
        var ids=new HashSet<String>();for(var output:outbox)if(!ids.add(output.id()))throw new IOException("duplicate output identity");
        for(var output:transaction.outputs()){if(!ids.add(output.id())||touched.contains(output.id()))throw new IOException("duplicate output operation");outbox.add(output);}
        touched.clear();for(String key:transaction.removeReceipts())if(!touched.add(key)||receipts.remove(key)==null)throw new IOException("invalid receipt removal");
        for(var entry:transaction.receipts().entrySet()){
            if(touched.contains(entry.getKey())||receipts.containsKey(entry.getKey())||!entry.getKey().matches("[a-f0-9]{64}")||!entry.getValue().matches("[a-f0-9]{64}"))throw new IOException("invalid receipt operation");receipts.put(entry.getKey(),entry.getValue());
        }
        if(transaction.receiptOrder()!=null){
            if(transaction.receiptOrder().size()!=receipts.size()||!new HashSet<>(transaction.receiptOrder()).equals(receipts.keySet()))throw new IOException("invalid receipt order");
            var ordered=new LinkedHashMap<String,String>();for(String key:transaction.receiptOrder())ordered.put(key,receipts.get(key));receipts=ordered;
        }
        return new S2SStreamAssembler.State(old.configuration(),pending,outbox,receipts,transaction.blocked());
    }

    // Tagged native values are storage grammar, shared by replay and the writer.
    static Object encode(Object value){
        if(value instanceof Map<?,?> map)return Map.of("map",map.entrySet().stream().map(e->Arrays.asList(e.getKey(),encode(e.getValue()))).toList());
        if(value instanceof List<?> list)return Map.of("list",list.stream().map(S2SAssemblyReader::encode).toList());
        if(value instanceof org.logstash.Timestamp timestamp)return Map.of("timestamp",timestamp.toString());
        if(value instanceof Number number)return Map.of("number",List.of(number.getClass().getSimpleName(),number.toString()));
        return value;
    }
    static Object decode(Object value){
        return decode(value,Integer.MAX_VALUE);
    }
    private static Object decode(Object value,int numericLimit){
        if(!(value instanceof Map<?,?> map)){
            if(value==null||value instanceof String||value instanceof Boolean)return value;
            throw new IllegalArgumentException("untagged assembly value");
        }
        if(map.size()!=1)throw new IllegalArgumentException("ambiguous assembly tag");
        if(map.containsKey("map")){
            Map<String,Object> result=new LinkedHashMap<>();
            if(!(map.get("map") instanceof List<?> pairs))throw new IllegalArgumentException("invalid assembly map");
            for(Object item:pairs){
                if(!(item instanceof List<?> pair)||pair.size()!=2||!(pair.get(0) instanceof String key)||result.containsKey(key))throw new IllegalArgumentException("invalid assembly map pair/key");
                result.put(key,decode(pair.get(1),numericLimit));
            }return result;
        }
        if(map.containsKey("list")){
            if(!(map.get("list") instanceof List<?> list))throw new IllegalArgumentException("invalid assembly list");
            return list.stream().map(item->decode(item,numericLimit)).toList();
        }
        if(map.containsKey("timestamp")){
            if(!(map.get("timestamp") instanceof String text))throw new IllegalArgumentException("invalid assembly timestamp");
            return new org.logstash.Timestamp(java.time.Instant.parse(text));
        }
        if(!(map.get("number") instanceof List<?> pair)||pair.size()!=2||!(pair.get(0) instanceof String)||!(pair.get(1) instanceof String text))throw new IllegalArgumentException("invalid assembly number");
        if(text.length()>numericLimit)throw new NumericBudgetException();
        return switch((String)pair.get(0)){
            case "Long" -> Long.valueOf(text);case "Integer" -> Integer.valueOf(text);
            case "Double" -> {double number=Double.parseDouble(text);if(!Double.isFinite(number))throw new IllegalArgumentException("nonfinite assembly number");yield number;}
            case "BigInteger" -> new java.math.BigInteger(text);case "BigDecimal" -> new java.math.BigDecimal(text);
            default -> throw new IllegalArgumentException("invalid assembly numeric type");
        };
    }
    @SuppressWarnings("unchecked") static Map<String,Object> envelope(Object value){Object decoded=decode(value);if(!(decoded instanceof Map<?,?>))throw new IllegalArgumentException("invalid assembly envelope");return (Map<String,Object>)decoded;}
    static final class NumericBudgetException extends IllegalArgumentException {}

    /** Structural/native validation shared with ingestion, deliberately independent of finalization policy. */
    static void validateStructure(S2SStreamAssembler.State value,java.util.function.Predicate<S2SStreamAssembler.Pending> known)throws IOException{
        validateStructure(value,known,Integer.MAX_VALUE);
    }
    private static void validateStructure(S2SStreamAssembler.State value,java.util.function.Predicate<S2SStreamAssembler.Pending> known,int numericLimit)throws IOException{
        try{
            if(value.configuration()==null||value.pending()==null||value.outbox()==null||value.receipts()==null)throw new IOException("invalid assembly state");
            if(value.pending().size()>10000||value.outbox().size()>40000||value.receipts().size()>4096)throw new BudgetException();
            var ids=new HashSet<String>();
            for(var entry:value.pending().entrySet()){
                var pending=entry.getValue();
                if(pending==null||pending.text()==null||pending.delimiter()==null||pending.origin()==null||pending.attributes()==null||pending.contributions()==null||
                    !entry.getKey().matches("[a-f0-9]{64}")||pending.contributions().isEmpty()||pending.timeout()<1||pending.eventLimit()<1||pending.touched()<0||
                    !Set.of("","\n","\r\n").contains(pending.delimiter())||!pending.origin().matches("[a-f0-9]{64}")||!pending.attributes().matches("[a-f0-9]{64}")||
                    !pending.chain().matches("[a-f0-9]{64}")||!pending.rule().matches("[a-f0-9]{64}"))throw new IOException("invalid assembly pending state");
                validateTemplate(decode(pending.envelope(),numericLimit),numericLimit);
                if(!known.test(pending))for(Object contribution:pending.contributions().suffix)validateContribution(contribution,numericLimit);
            }
            for(var output:value.outbox()){
                if(output.id()==null||!ids.add(output.id()))throw new IOException("duplicate assembly output identity");
                validateTemplate(decode(output.envelope(),numericLimit),numericLimit);
            }
            for(var receipt:value.receipts().entrySet())if(!receipt.getKey().matches("[a-f0-9]{64}")||!receipt.getValue().matches("[a-f0-9]{64}"))throw new IOException("invalid assembly receipt");
        }catch(NumericBudgetException error){throw new BudgetException();}
        catch(RuntimeException error){throw new IOException("invalid assembly historical state",error);}
    }
    private static void validateContribution(Object value,int numericLimit){
        if(!(value instanceof Map<?,?> map))throw new IllegalArgumentException("invalid assembly contribution");
        for(String key:List.of("offset","sequence","line","logical_offset")){
            Object coordinate=map.get(key);
            if(!(coordinate instanceof Long||coordinate instanceof Integer)||((Number)coordinate).longValue()<(key.equals("line")?0:-1))throw new IllegalArgumentException("invalid assembly contribution coordinate");
        }
        if(!(map.get("sha256") instanceof String hash)||!hash.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("invalid assembly contribution digest");
        if(map.containsKey("wire")&&!(decode(map.get("wire"),numericLimit) instanceof Map<?,?>))throw new IllegalArgumentException("invalid assembly contribution wire template");
    }
    private static void validateTemplate(Object value,int numericLimit){
        if(!(value instanceof Map<?,?> map))throw new IllegalArgumentException("invalid assembly envelope");
        for(String key:List.of("host","source","index","sourcetype","@version"))if(map.containsKey(key)&&!(map.get(key) instanceof String))throw new IllegalArgumentException("invalid assembly envelope field");
        if(map.containsKey("@timestamp")&&!(map.get("@timestamp") instanceof org.logstash.Timestamp))throw new IllegalArgumentException("invalid assembly timestamp field");
        if(map.containsKey("@metadata")&&!(map.get("@metadata") instanceof Map<?,?>))throw new IllegalArgumentException("invalid assembly metadata field");
        if(map.containsKey("fields")){
            if(!(map.get("fields") instanceof Map<?,?> fields))throw new IllegalArgumentException("invalid assembly indexed fields");
            for(Object field:fields.values())if(field instanceof Map<?,?>||field instanceof List<?> list&&list.stream().anyMatch(item->item instanceof Map<?,?>||item instanceof List<?>))throw new IllegalArgumentException("invalid assembly indexed field");
        }
        validateNative(value,numericLimit);
    }
    private static void validateNative(Object value,int numericLimit){
        if(value instanceof String text)HecProtocol.unicode(text);
        if(value instanceof java.math.BigDecimal number&&(Math.abs((long)number.scale())>numericLimit||number.precision()>numericLimit))throw new NumericBudgetException();
        if(value instanceof Map<?,?> map)map.forEach((key,item)->{if(!(key instanceof String))throw new IllegalArgumentException("invalid assembly key");validateNative(key,numericLimit);validateNative(item,numericLimit);});
        if(value instanceof List<?> list)list.forEach(item->validateNative(item,numericLimit));
    }
    /** Caps both retained state and cumulative validation/serialization work, including replay amplification. */
    static final class Validation implements S2SAssemblyStore.Validator {
        private long remaining=1L<<30;
        @Override public void validate(S2SStreamAssembler.State state)throws IOException{
            validateStructure(state,p->false,1024);
            long contributions=0;
            for(var pending:state.pending().values()){
                contributions+=pending.contributions().size();
                if(contributions>1000000)throw new BudgetException();
            }
            class Counter extends OutputStream{
                long count;
                @Override public void write(int b)throws IOException{add(1);}
                @Override public void write(byte[] b,int off,int n)throws IOException{add(n);}
                void add(int n)throws IOException{
                    if(n>S2SAssemblyStore.SAFETY_MAXIMUM-count||n>remaining)throw new BudgetException();
                    count+=n;remaining-=n;
                }
            }
            HecProtocol.JSON.writeValue(new Counter(),state);
        }
    }
    private S2SAssemblyReader(){}
}
