package org.logstashplugins.hec;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/** Single-writer authenticated delta journal with durable generation publication. */
final class S2SAssemblyStore implements AutoCloseable {
    private final Path directory,state,next;
    private final long maximum;
    private final long historyLimit,physicalLimit;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private boolean failed;
    private long generation,sequence,journalBytes;
    private S2SStreamAssembler.State current;
    private byte[] legacy;
    private boolean migration;
    private boolean recoveryCompaction;
    interface Faults {void at(String boundary)throws IOException;}
    interface Validator {void validate(S2SStreamAssembler.State state)throws IOException;}
    private final Faults faults;
    private static final int MAGIC=0x53325333,HEADER=88;
    static final long SAFETY_MAXIMUM=67108863L;
    private static final long RECOVERY_HISTORY=2*SAFETY_MAXIMUM+4096,RECOVERY_PHYSICAL=8*SAFETY_MAXIMUM+32768;
    record Pointer(long generation,long sequence,String snapshot) {}
    record Snapshot(long sequence,S2SStreamAssembler.State state) {}
    record Change(String key,String prior,S2SStreamAssembler.Pending value,String text,List<Object> contributions) {}
    record Transaction(String configuration,List<String> removePending,List<Change> pending,List<String> removeOutputs,
                       List<S2SStreamAssembler.Output> outputs,List<String> removeReceipts,Map<String,String> receipts,List<String> receiptOrder,List<String> pendingOrder,boolean blocked) {}
    S2SAssemblyStore(Path directory,long maximum)throws IOException{
        this(directory,maximum,boundary->{});
    }
    S2SAssemblyStore(Path directory,long maximum,Faults faults)throws IOException{
        this.directory=directory;this.maximum=maximum;
        this.faults=faults;historyLimit=Math.addExact(Math.multiplyExact(maximum,2),4096);
        physicalLimit=Math.addExact(Math.multiplyExact(maximum,8),32768);
        Files.createDirectories(directory);
        if(Files.isSymbolicLink(directory))throw new IOException("assembly directory must be private regular storage");
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));
        // Persist the assembly-directory entry itself before any first acknowledgement.
        try(FileChannel parent=FileChannel.open(directory.toAbsolutePath().getParent(),StandardOpenOption.READ)){parent.force(true);}
        state=directory.resolve("state");next=directory.resolve("next");
        Path lockPath=directory.resolve("lock");
        lockChannel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
        try{
            lock=lockChannel.tryLock();if(lock==null)throw new IOException("assembly state is already locked");
            Files.setPosixFilePermissions(lockPath,PosixFilePermissions.fromString("rw-------"));
        }catch(IOException|RuntimeException error){lockChannel.close();throw error;}
    }
    private com.fasterxml.jackson.databind.ObjectMapper mapper(){return S2SStreamAssembler.recoveryMapper(RECOVERY_PHYSICAL);}
    byte[] recover()throws IOException{
        return recover(value->{});
    }
    byte[] recover(Validator validator)throws IOException{
        if(physicalBytes()>RECOVERY_PHYSICAL)throw new IOException("assembly recovery physical safety bound exceeded");
        Path pointer=directory.resolve("current-v3");
        if(Files.exists(pointer,LinkOption.NOFOLLOW_LINKS)){
            Pointer published=mapper().readValue(checked(pointer,4096),Pointer.class);
            if(published.generation<1||published.sequence<0||!published.snapshot.matches("[a-f0-9]{64}"))throw new IOException("invalid assembly generation pointer");
            generation=published.generation;
            byte[] snapshotBytes=checked(snapshot(generation),SAFETY_MAXIMUM+4096);
            if(!TokenStore.fingerprint(snapshotBytes).equals(published.snapshot))throw new IOException("assembly generation mismatch");
            Snapshot snapshot=mapper().readValue(snapshotBytes,Snapshot.class);
            if(snapshot.sequence!=published.sequence)throw new IOException("assembly snapshot sequence mismatch");
            sequence=snapshot.sequence;current=snapshot.state;validator.validate(current);
            Path journal=journal(generation);regular(journal,RECOVERY_HISTORY);
            try(FileChannel file=FileChannel.open(journal,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                long position=0,total=file.size();
                while(position<total){
                    if(total-position<HEADER){truncate(file,position);break;}
                    byte[] header=new byte[HEADER];read(file,position,header);
                    ByteBuffer framing=ByteBuffer.wrap(header);
                    int magic=framing.getInt(),version=framing.getInt();long ordinal=framing.getLong(),length=framing.getLong();
                    if(magic!=MAGIC||version!=3||ordinal!=sequence+1||length<0||length>RECOVERY_HISTORY-HEADER||
                        !Arrays.equals(Arrays.copyOfRange(header,24,56),digest(Arrays.copyOfRange(header,0,24))))throw new IOException("corrupt assembly transaction framing/sequence");
                    if(total-position-HEADER<length){truncate(file,position);break;}
                    byte[] payload=new byte[(int)length];read(file,position+HEADER,payload);
                    if(!Arrays.equals(Arrays.copyOfRange(header,56,88),digest(payload)))throw new IOException("assembly transaction checksum mismatch");
                    Transaction transaction=mapper().readValue(payload,Transaction.class);
                    current=apply(current,transaction);validator.validate(current);sequence=ordinal;position+=HEADER+length;
                }
                journalBytes=file.size();
            }catch(RuntimeException error){throw new IOException("invalid assembly transaction",error);}
            return HecProtocol.JSON.writeValueAsBytes(current);
        }
        requireInitialPublication();
        Path backup=directory.resolve("backup-v2");
        if(Files.exists(state,LinkOption.NOFOLLOW_LINKS)){
            try{legacy=checked(state,SAFETY_MAXIMUM);}
            catch(IOException invalid){
                if(markerEquals(state,freshRefusal()))return null;
                // Only the exact refusal marker proves migration was interrupted; corruption is never fallback evidence.
                if(!markerEquals(state,refusal()))throw invalid;
                legacy=checked(backup,SAFETY_MAXIMUM);
            }
            migration=true;return legacy;
        }
        if(Files.exists(backup,LinkOption.NOFOLLOW_LINKS))throw new IOException("assembly migration backup without original state");
        return null;
    }
    void initialize(S2SStreamAssembler.State validated)throws IOException{
        current=validated;
        if(generation>0){
            // The rename may be visible after an interrupted directory fsync. Make
            // that observation durable BEFORE deleting either referenced generation.
            sync("recovered-pointer-directory");
            establish();cleanup();
            Path backup=directory.resolve("backup-v2");
            long backupBytes=Files.exists(backup,LinkOption.NOFOLLOW_LINKS)?Files.size(backup):0;
            if(backupBytes+serializedSize(new Snapshot(sequence,validated))+8192>physicalLimit)
                throw new IOException("preserved assembly backup cannot fit configured physical quota");
            if(journalBytes>historyLimit||physicalBytes()>physicalLimit){
                recoveryCompaction=true;
                try{publish(validated);}finally{recoveryCompaction=false;}
            }
            checkPhysical();return;
        }
        if(!migration)return;
        try{
            Path backup=directory.resolve("backup-v2");
            if(Files.exists(backup,LinkOption.NOFOLLOW_LINKS)){
                if(!Arrays.equals(checked(backup,maximum),legacy))throw new IOException("assembly migration backup mismatch");
                // A prior crash may have followed rename but preceded directory fsync.
                sync("migration-backup-directory");
            }else{
                Path temporary=directory.resolve("backup-next-v2");durable(temporary,wrap(legacy),"migration-backup");
                faults.at("migration-backup-move");Files.move(temporary,backup,StandardCopyOption.ATOMIC_MOVE);sync("migration-backup-directory");
            }
            durable(next,refusal(),"migration-marker");
            faults.at("migration-marker-move");Files.move(next,state,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);sync("migration-marker-directory");
            publish(validated);establish();legacy=null;
        }catch(IOException error){failed=true;throw error;}
    }
    private byte[] checked(Path path,long bound)throws IOException{
        regular(path,bound+65);byte[] bytes=Files.readAllBytes(path);
        if(bytes.length<65||bytes[64]!='\n')throw new IOException("corrupt assembly snapshot");
        byte[] payload=Arrays.copyOfRange(bytes,65,bytes.length);
        if(!TokenStore.fingerprint(payload).equals(new String(bytes,0,64,StandardCharsets.US_ASCII)))throw new IOException("assembly checksum mismatch");
        return payload;
    }
    void commit(S2SStreamAssembler.State value)throws IOException{
        if(failed)throw new IOException("assembly storage is blocked");
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(delta(current,value));
        if(payload.length>historyLimit-HEADER)throw new IOException("assembly transaction quota exceeded");
        try{
            if(generation==0){
                // The legacy reader ignores current-v3. Refuse it before any v3 publication.
                durable(next,freshRefusal(),"fresh-marker");faults.at("fresh-marker-move");
                Files.move(next,state,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);sync("fresh-marker-directory");
                publish(current);establish();
            }else if(journalBytes+HEADER+payload.length>historyLimit)publish(current);
            checkPhysical();
            if(physicalBytes()+HEADER+payload.length>physicalLimit)throw new IOException("assembly physical quota exceeded");
            ByteBuffer header=ByteBuffer.allocate(HEADER).putInt(MAGIC).putInt(3).putLong(sequence+1).putLong(payload.length);
            header.put(digest(Arrays.copyOf(header.array(),24))).put(digest(payload));
            try(FileChannel file=FileChannel.open(journal(generation),StandardOpenOption.WRITE,StandardOpenOption.APPEND,LinkOption.NOFOLLOW_LINKS)){
                faults.at("append-header");write(file,header.array());faults.at("append-payload");write(file,payload);
                faults.at("append-sync");file.force(true);faults.at("append-durable");
            }
            journalBytes+=HEADER+payload.length;sequence++;current=value;
        }catch(IOException error){failed=true;throw new IOException("assembly commit failed; storage blocked",error);}
    }
    private Transaction delta(S2SStreamAssembler.State old,S2SStreamAssembler.State value){
        var changes=new ArrayList<Change>();
        for(var entry:value.pending().entrySet()){
            var before=old.pending().get(entry.getKey());var after=entry.getValue();if(before==after)continue;
            if(before!=null&&before.envelope()==after.envelope()&&before.eventLimit()==after.eventLimit()&&before.timeout()==after.timeout()&&
                before.rule().equals(after.rule())&&before.origin().equals(after.origin())&&before.attributes().equals(after.attributes())&&Objects.equals(before.sender(),after.sender())){
                try{
                    String suffix=after.text().since(before.text());var contributions=after.contributions().since(before.contributions());
                    var template=new S2SStreamAssembler.Pending(null,new AssemblyChunks.Text(""),after.delimiter(),after.rule(),after.chain(),after.attributes(),after.origin(),
                        new AssemblyChunks.Contributions(List.of()),after.touched(),after.timeout(),after.offset(),after.sequence(),after.eventLimit(),after.sender());
                    changes.add(new Change(entry.getKey(),before.chain(),template,suffix,contributions));continue;
                }catch(IllegalArgumentException notAncestor){/* replacement after a staged completion */}
            }
            changes.add(new Change(entry.getKey(),null,after,null,null));
        }
        var ids=new HashSet<String>();for(var output:value.outbox())ids.add(output.id());
        var oldIds=new HashSet<String>();for(var output:old.outbox())oldIds.add(output.id());
        var receipts=new LinkedHashMap<String,String>();value.receipts().forEach((key,content)->{if(!content.equals(old.receipts().get(key)))receipts.put(key,content);});
        var natural=new LinkedHashMap<>(old.receipts());natural.keySet().retainAll(value.receipts().keySet());natural.putAll(receipts);
        List<String> receiptOrder=new ArrayList<>(natural.keySet()).equals(new ArrayList<>(value.receipts().keySet()))?null:List.copyOf(value.receipts().keySet());
        var naturalPending=new LinkedHashMap<>(old.pending());naturalPending.keySet().retainAll(value.pending().keySet());naturalPending.putAll(value.pending());
        List<String> pendingOrder=new ArrayList<>(naturalPending.keySet()).equals(new ArrayList<>(value.pending().keySet()))?null:List.copyOf(value.pending().keySet());
        return new Transaction(value.configuration(),old.pending().keySet().stream().filter(key->!value.pending().containsKey(key)).toList(),changes,
            old.outbox().stream().map(S2SStreamAssembler.Output::id).filter(id->!ids.contains(id)).toList(),value.outbox().stream().filter(output->!oldIds.contains(output.id())).toList(),
            old.receipts().keySet().stream().filter(key->!value.receipts().containsKey(key)).toList(),receipts,receiptOrder,pendingOrder,value.blocked());
    }
    static S2SStreamAssembler.State apply(S2SStreamAssembler.State old,Transaction transaction)throws IOException{
        if(!old.configuration().equals(transaction.configuration))throw new IOException("assembly transaction configuration mismatch");
        var pending=new LinkedHashMap<>(old.pending());var outbox=new ArrayList<>(old.outbox());var receipts=new LinkedHashMap<>(old.receipts());
        var touched=new HashSet<String>();
        for(String key:transaction.removePending)if(!touched.add(key)||pending.remove(key)==null)throw new IOException("invalid pending removal");
        for(Change change:transaction.pending){
            if(!touched.add(change.key))throw new IOException("duplicate pending operation");
            var value=change.value;
            if(change.prior!=null){
                var before=pending.get(change.key);
                if(before==null||!before.chain().equals(change.prior)||value.text().length()!=0||!value.contributions().isEmpty()||
                    value.envelope()!=null||!before.rule().equals(value.rule())||!before.origin().equals(value.origin())||!before.attributes().equals(value.attributes())||
                    before.timeout()!=value.timeout()||before.eventLimit()!=value.eventLimit()||!Objects.equals(before.sender(),value.sender()))throw new IOException("invalid pending append");
                value=new S2SStreamAssembler.Pending(before.envelope(),new AssemblyChunks.Text(before.text(),change.text),value.delimiter(),value.rule(),value.chain(),value.attributes(),value.origin(),
                    new AssemblyChunks.Contributions(before.contributions(),change.contributions),value.touched(),value.timeout(),value.offset(),value.sequence(),value.eventLimit(),value.sender());
            }else if(change.text!=null||change.contributions!=null)throw new IOException("invalid pending replacement");
            pending.put(change.key,value);
        }
        if(transaction.pendingOrder!=null){
            if(transaction.pendingOrder.size()!=pending.size()||!new HashSet<>(transaction.pendingOrder).equals(pending.keySet()))throw new IOException("invalid pending order");
            var ordered=new LinkedHashMap<String,S2SStreamAssembler.Pending>();for(String key:transaction.pendingOrder)ordered.put(key,pending.get(key));pending=ordered;
        }
        touched.clear();for(String id:transaction.removeOutputs){if(!touched.add(id)||!outbox.removeIf(output->output.id().equals(id)))throw new IOException("invalid output removal");}
        var ids=new HashSet<String>();for(var output:outbox)if(!ids.add(output.id()))throw new IOException("duplicate output identity");
        for(var output:transaction.outputs){if(!ids.add(output.id())||touched.contains(output.id()))throw new IOException("duplicate output operation");outbox.add(output);}
        touched.clear();for(String key:transaction.removeReceipts)if(!touched.add(key)||receipts.remove(key)==null)throw new IOException("invalid receipt removal");
        for(var entry:transaction.receipts.entrySet()){
            if(touched.contains(entry.getKey())||receipts.containsKey(entry.getKey())||!entry.getKey().matches("[a-f0-9]{64}")||!entry.getValue().matches("[a-f0-9]{64}"))throw new IOException("invalid receipt operation");receipts.put(entry.getKey(),entry.getValue());
        }
        if(transaction.receiptOrder!=null){
            if(transaction.receiptOrder.size()!=receipts.size()||!new HashSet<>(transaction.receiptOrder).equals(receipts.keySet()))throw new IOException("invalid receipt order");
            var ordered=new LinkedHashMap<String,String>();for(String key:transaction.receiptOrder)ordered.put(key,receipts.get(key));receipts=ordered;
        }
        return new S2SStreamAssembler.State(old.configuration(),pending,outbox,receipts,transaction.blocked);
    }
    private Path snapshot(long id){return directory.resolve("snapshot-v3-"+id);}
    private Path journal(long id){return directory.resolve("journal-v3-"+id);}
    void compact()throws IOException{publish(current);}
    private void publish(S2SStreamAssembler.State value)throws IOException{
        cleanup();long id=Math.addExact(generation,1);
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(new Snapshot(sequence,value));
        if(payload.length>maximum+4096)throw new IOException("assembly snapshot quota exceeded");
        if(physicalBytes()+payload.length+8192>writePhysicalLimit())throw new IOException("assembly compaction physical quota exceeded");
        durable(snapshot(id),wrap(payload),"snapshot");durable(journal(id),new byte[0],"journal");sync("generation-directory");
        durable(directory.resolve("pointer-next-v3"),wrap(HecProtocol.JSON.writeValueAsBytes(new Pointer(id,sequence,TokenStore.fingerprint(payload)))),"pointer");
        faults.at("pointer-move");Files.move(directory.resolve("pointer-next-v3"),directory.resolve("current-v3"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        sync("pointer-directory");generation=id;journalBytes=0;faults.at("publication-durable");cleanup();
    }
    private void cleanup()throws IOException{
        try(var files=Files.newDirectoryStream(directory)){
            for(Path path:files){String name=path.getFileName().toString();
                if(name.matches("(snapshot|journal)-v3-[0-9]+")&&!path.equals(snapshot(generation))&&!path.equals(journal(generation))||name.equals("pointer-next-v3")||name.equals("backup-next-v2")){
                    if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("invalid assembly generation file");faults.at("cleanup");Files.delete(path);
                }
            }
        }
        sync("cleanup-directory");
    }
    private void durable(Path path,byte[] bytes,String boundary)throws IOException{
        long existing=Files.exists(path,LinkOption.NOFOLLOW_LINKS)?Files.size(path):0;
        if(physicalBytes()-existing+bytes.length>writePhysicalLimit())throw new IOException("assembly physical quota exceeded");
        faults.at(boundary+"-write");
        try(FileChannel file=FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
            Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));write(file,bytes);faults.at(boundary+"-sync");file.force(true);
        }
        faults.at(boundary+"-durable");
    }
    private void sync(String boundary)throws IOException{faults.at(boundary);try(FileChannel dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}}
    private static byte[] refusal(){return "S2S assembly migrated to v3; restore backup-v2 to downgrade\n".getBytes(StandardCharsets.US_ASCII);}
    private static byte[] freshRefusal(){return "S2S assembly v3; downgrade requires explicit state recovery\n".getBytes(StandardCharsets.US_ASCII);}
    private long writePhysicalLimit(){return recoveryCompaction?RECOVERY_PHYSICAL:physicalLimit;}
    private void establish()throws IOException{
        Path established=directory.resolve("established-v3");
        if(!Files.exists(established,LinkOption.NOFOLLOW_LINKS))durable(established,new byte[]{3},"established");
        else{
            if(!markerEquals(established,new byte[]{3}))throw new IOException("invalid assembly established marker");
            // An interrupted first force may leave valid visible bytes without durable contents.
            try(FileChannel file=FileChannel.open(established,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                faults.at("established-recovery-sync");file.force(true);
            }
        }
        sync("established-directory");
    }
    /** Only an unacknowledged first publication may be rebuilt without a pointer. */
    private void requireInitialPublication()throws IOException{
        if(Files.exists(directory.resolve("established-v3"),LinkOption.NOFOLLOW_LINKS))throw new IOException("assembly published pointer missing");
        try(var files=Files.newDirectoryStream(directory)){
            for(Path path:files){String name=path.getFileName().toString();
                if(name.matches("(snapshot|journal)-v3-[0-9]+")){
                    if(!name.endsWith("-1")||name.startsWith("journal-")&&Files.size(path)!=0)
                        throw new IOException("ambiguous assembly state without published pointer");
                }
            }
        }
    }
    private static boolean markerEquals(Path path,byte[] marker)throws IOException{
        if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)!=marker.length)return false;
        byte[] bytes=new byte[marker.length];
        try(FileChannel file=FileChannel.open(path,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)){read(file,0,bytes);}
        return Arrays.equals(bytes,marker);
    }
    private static byte[] wrap(byte[] payload){byte[] prefix=(TokenStore.fingerprint(payload)+"\n").getBytes(StandardCharsets.US_ASCII);byte[] result=Arrays.copyOf(prefix,prefix.length+payload.length);System.arraycopy(payload,0,result,prefix.length,payload.length);return result;}
    private static byte[] digest(byte[] bytes){return java.util.HexFormat.of().parseHex(TokenStore.fingerprint(bytes));}
    private static void regular(Path path,long bound)throws IOException{if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>bound)throw new IOException("invalid assembly snapshot/journal size/type");}
    private long physicalBytes()throws IOException{long bytes=0;try(var files=Files.newDirectoryStream(directory)){for(Path path:files){if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("invalid assembly storage file");bytes=Math.addExact(bytes,Files.size(path));}}return bytes;}
    private void checkPhysical()throws IOException{if(physicalBytes()>physicalLimit)throw new IOException("assembly physical quota exceeded");}
    private void truncate(FileChannel file,long position)throws IOException{faults.at("recovery-truncate");file.truncate(position);file.force(true);}
    private static void read(FileChannel channel,long position,byte[] bytes)throws IOException{ByteBuffer buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining()){int n=channel.read(buffer,position+buffer.position());if(n<0)throw new EOFException();}}
    /** Count the actual JSON bytes without retaining another serialized snapshot. */
    long serializedSize(Object value)throws IOException{
        class Counter extends OutputStream{
            long count;
            @Override public void write(int b)throws IOException{add(1);}
            @Override public void write(byte[] b,int off,int n)throws IOException{add(n);}
            private void add(int n)throws IOException{
                if(n>RECOVERY_PHYSICAL-count)throw new IOException("assembly quota exceeded");
                count+=n;
            }
        }
        var counter=new Counter();HecProtocol.JSON.writeValue(counter,value);return counter.count;
    }
    void validateCapacity(Object value,long reserved)throws IOException{
        validateCapacity(serializedSize(value),reserved);
    }
    void validateCapacity(long bytes,long reserved)throws IOException{if(bytes<0||reserved<0||reserved>maximum||bytes>maximum-reserved)throw new IOException("assembly finalization quota exceeded");}
    private static void write(FileChannel channel,byte[] bytes)throws IOException{
        var buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining())channel.write(buffer);
    }
    boolean failed(){return failed;}
    @Override public void close()throws IOException{try{lock.release();}finally{lockChannel.close();}}

    // Explicit tagged values preserve numeric types (including negative zero) and native Timestamp.
    // ALL maps are represented as pairs so application keys cannot collide with codec tags.
    static Object encode(Object value){
        if(value instanceof Map<?,?> map)return Map.of("map",map.entrySet().stream().map(e->Arrays.asList(e.getKey(),encode(e.getValue()))).toList());
        if(value instanceof List<?> list)return Map.of("list",list.stream().map(S2SAssemblyStore::encode).toList());
        if(value instanceof org.logstash.Timestamp timestamp)return Map.of("timestamp",timestamp.toString());
        if(value instanceof Number number)return Map.of("number",List.of(number.getClass().getSimpleName(),number.toString()));
        return value;
    }
    static Object decode(Object value){
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
                result.put(key,decode(pair.get(1)));
            }return result;
        }
        if(map.containsKey("list")){
            if(!(map.get("list") instanceof List<?> list))throw new IllegalArgumentException("invalid assembly list");
            return list.stream().map(S2SAssemblyStore::decode).toList();
        }
        if(map.containsKey("timestamp")){
            if(!(map.get("timestamp") instanceof String text))throw new IllegalArgumentException("invalid assembly timestamp");
            return new org.logstash.Timestamp(java.time.Instant.parse(text));
        }
        if(!(map.get("number") instanceof List<?> pair)||pair.size()!=2||!(pair.get(0) instanceof String)||!(pair.get(1) instanceof String text))throw new IllegalArgumentException("invalid assembly number");
        return switch((String)pair.get(0)){
            case "Long" -> Long.valueOf(text);case "Integer" -> Integer.valueOf(text);
            case "Double" -> {double number=Double.parseDouble(text);if(!Double.isFinite(number))throw new IllegalArgumentException("nonfinite assembly number");yield number;}
            case "BigInteger" -> new java.math.BigInteger(text);case "BigDecimal" -> new java.math.BigDecimal(text);
            default -> throw new IllegalArgumentException("invalid assembly numeric type");
        };
    }
    @SuppressWarnings("unchecked") static Map<String,Object> envelope(Object value){Object decoded=decode(value);if(!(decoded instanceof Map<?,?>))throw new IllegalArgumentException("invalid assembly envelope");return (Map<String,Object>)decoded;}
}
