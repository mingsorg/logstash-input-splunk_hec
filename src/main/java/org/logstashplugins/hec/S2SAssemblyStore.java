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
    private String recoveryOrigin;
    private S2SStreamAssembler.State current;
    private byte[] legacy;
    private boolean migration;
    private boolean recoveryCompaction;
    interface Faults {void at(String boundary)throws IOException;}
    interface Validator {void validate(S2SStreamAssembler.State state)throws IOException;}
    private final Faults faults;
    private final HecMetrics metrics;
    private static final int MAGIC=S2SAssemblyReader.MAGIC,HEADER=S2SAssemblyReader.HEADER;
    static final long SAFETY_MAXIMUM=67108863L;
    private static final long RECOVERY_HISTORY=2*SAFETY_MAXIMUM+4096,RECOVERY_PHYSICAL=8*SAFETY_MAXIMUM+32768;
    record Pointer(long generation,long sequence,String snapshot) {}
    record Snapshot(long sequence,S2SStreamAssembler.State state,
                    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) String recoveryOrigin) {
        Snapshot(long sequence,S2SStreamAssembler.State state){this(sequence,state,null);}
    }
    static S2SAssemblyRecovery.Origin checkRecoveryOrigin(Snapshot snapshot,byte[] metadata)throws IOException{
        String expected=snapshot.recoveryOrigin();
        if(expected==null){if(metadata!=null)throw new IOException("unbound assembly recovery provenance");return null;}
        if(!expected.matches("[a-f0-9]{64}")||metadata==null||!expected.equals(TokenStore.fingerprint(metadata)))throw new IOException("assembly recovery provenance missing or mismatched");
        return S2SAssemblyRecovery.readOrigin(metadata);
    }
    record Change(String key,String prior,S2SStreamAssembler.Pending value,String text,List<Object> contributions) {}
    record Transaction(String configuration,List<String> removePending,List<Change> pending,List<String> removeOutputs,
                       List<S2SStreamAssembler.Output> outputs,List<String> removeReceipts,Map<String,String> receipts,List<String> receiptOrder,List<String> pendingOrder,boolean blocked) {}
    S2SAssemblyStore(Path directory,long maximum)throws IOException{
        this(directory,maximum,boundary->{});
    }
    S2SAssemblyStore(Path directory,long maximum,Faults faults)throws IOException{
        this(directory,maximum,faults,HecMetrics.NONE);
    }
    S2SAssemblyStore(Path directory,long maximum,Faults faults,HecMetrics metrics)throws IOException{
        this.directory=directory;this.maximum=maximum;
        this.metrics=metrics;
        this.faults=faults;historyLimit=Math.addExact(Math.multiplyExact(maximum,2),4096);
        physicalLimit=Math.addExact(Math.multiplyExact(maximum,8),32768);
        Files.createDirectories(directory);
        if(Files.isSymbolicLink(directory))throw new IOException("assembly directory must be private regular storage");
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));
        // Persist the assembly-directory entry itself before any first acknowledgement.
        try(FileChannel parent=FileChannel.open(directory.toAbsolutePath().getParent(),StandardOpenOption.READ)){force(parent);}
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
        if(Files.exists(directory.resolve("recovery-incomplete"),LinkOption.NOFOLLOW_LINKS))throw new IOException("incomplete operator rebuild; explicit recovery required");
        if(physicalBytes()>RECOVERY_PHYSICAL)throw new IOException("assembly recovery physical safety bound exceeded");
        Path pointer=directory.resolve("current-v3");
        if(Files.exists(pointer,LinkOption.NOFOLLOW_LINKS)){
            Pointer published=S2SAssemblyReader.pointer(checked(pointer,4096),mapper());
            generation=published.generation;
            byte[] snapshotBytes=checked(snapshot(generation),SAFETY_MAXIMUM+4096);
            Snapshot snapshot=S2SAssemblyReader.snapshot(snapshotBytes,published,mapper());
            Path origin=directory.resolve("recovery-origin-v1");
            byte[] metadata=null;
            if(Files.exists(origin,LinkOption.NOFOLLOW_LINKS)){regular(origin,16384);metadata=Files.readAllBytes(origin);}
            checkRecoveryOrigin(snapshot,metadata);recoveryOrigin=snapshot.recoveryOrigin();
            sequence=snapshot.sequence;current=snapshot.state;
            Path journal=journal(generation);regular(journal,RECOVERY_HISTORY);
            try(FileChannel file=FileChannel.open(journal,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                var replay=S2SAssemblyReader.replay(file,current,sequence,mapper(),validator,Long.MAX_VALUE);
                current=replay.state();sequence=replay.sequence();
                if(replay.prefix()<file.size())truncate(file,replay.prefix());
                journalBytes=file.size();
                metrics.set("assembly.journal_bytes_last_observed",journalBytes);
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
    /** Fresh destination only. No ingestion admission, delta, policy check, or source recovery. */
    static void publishRecovered(S2SSecureFiles.Destination destination,S2SStreamAssembler.State value,
                                 byte[] origin,S2SAssemblyInspector.Faults faults)throws IOException{
        new S2SAssemblyReader.Validation().validate(value);
        destination.write("lock",new byte[0],faults);
        destination.write("state",freshRefusal(),faults);
        byte[] metadata=wrap(origin);
        byte[] snapshot=HecProtocol.JSON.writeValueAsBytes(new Snapshot(0,value,TokenStore.fingerprint(metadata)));
        destination.write("snapshot-v3-1",wrap(snapshot),faults);
        destination.write("journal-v3-1",new byte[0],faults);
        destination.write("recovery-origin-v1",metadata,faults);
        destination.write("established-v3",new byte[]{3},faults);
        destination.write("current-v3",wrap(HecProtocol.JSON.writeValueAsBytes(new Pointer(1,0,TokenStore.fingerprint(snapshot)))),faults);
        destination.finish(faults);
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
        return S2SAssemblyReader.checked(bytes);
    }
    void commit(S2SStreamAssembler.State value)throws IOException{
        long start=metrics.begin("store.commit");boolean success=false;
        try{commitValue(value);success=true;metrics.timestamp("last_commit_epoch_millis");}
        finally{metrics.timed("store.commit",start,success);}
    }
    private void commitValue(S2SStreamAssembler.State value)throws IOException{
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
                force(file,"append-sync");faults.at("append-durable");
            }
            journalBytes+=HEADER+payload.length;sequence++;current=value;
            metrics.set("assembly.journal_bytes_last_observed",journalBytes);
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
        return S2SAssemblyReader.apply(old,transaction);
    }
    private Path snapshot(long id){return directory.resolve("snapshot-v3-"+id);}
    private Path journal(long id){return directory.resolve("journal-v3-"+id);}
    void compact()throws IOException{publish(current);}
    private void publish(S2SStreamAssembler.State value)throws IOException{
        long start=metrics.begin("store.publication");boolean success=false;
        boolean compaction=generation>0;long compactStart=compaction?metrics.begin("store.compaction"):0;
        try{publishValue(value);success=true;}finally{
            metrics.timed("store.publication",start,success);
            if(compaction)metrics.timed("store.compaction",compactStart,success);
        }
    }
    private void publishValue(S2SStreamAssembler.State value)throws IOException{
        cleanup();long id=Math.addExact(generation,1);
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(new Snapshot(sequence,value,recoveryOrigin));
        if(payload.length>maximum+4096)throw new IOException("assembly snapshot quota exceeded");
        if(physicalBytes()+payload.length+8192>writePhysicalLimit())throw new IOException("assembly compaction physical quota exceeded");
        durable(snapshot(id),wrap(payload),"snapshot");durable(journal(id),new byte[0],"journal");sync("generation-directory");
        durable(directory.resolve("pointer-next-v3"),wrap(HecProtocol.JSON.writeValueAsBytes(new Pointer(id,sequence,TokenStore.fingerprint(payload)))),"pointer");
        faults.at("pointer-move");Files.move(directory.resolve("pointer-next-v3"),directory.resolve("current-v3"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        sync("pointer-directory");generation=id;journalBytes=0;metrics.set("assembly.journal_bytes_last_observed",0);faults.at("publication-durable");cleanup();
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
            Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));write(file,bytes);force(file,boundary+"-sync");
        }
        faults.at(boundary+"-durable");
    }
    private void sync(String boundary)throws IOException{
        long start=metrics.begin("store.fsync");boolean success=false;
        try{faults.at(boundary);try(FileChannel dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}success=true;}
        finally{metrics.timed("store.fsync",start,success);}
    }
    private void force(FileChannel file)throws IOException{force(file,null);}
    private void force(FileChannel file,String boundary)throws IOException{
        long start=metrics.begin("store.fsync");boolean success=false;
        try{if(boundary!=null)faults.at(boundary);file.force(true);success=true;}finally{metrics.timed("store.fsync",start,success);}
    }
    private static byte[] refusal(){return S2SAssemblyReader.REFUSAL;}
    private static byte[] freshRefusal(){return S2SAssemblyReader.FRESH_REFUSAL;}
    private long writePhysicalLimit(){return recoveryCompaction?RECOVERY_PHYSICAL:physicalLimit;}
    private void establish()throws IOException{
        Path established=directory.resolve("established-v3");
        if(!Files.exists(established,LinkOption.NOFOLLOW_LINKS))durable(established,new byte[]{3},"established");
        else{
            if(!markerEquals(established,new byte[]{3}))throw new IOException("invalid assembly established marker");
            // An interrupted first force may leave valid visible bytes without durable contents.
            try(FileChannel file=FileChannel.open(established,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                force(file,"established-recovery-sync");
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
    private long physicalBytes()throws IOException{long bytes=0;try(var files=Files.newDirectoryStream(directory)){for(Path path:files){if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("invalid assembly storage file");bytes=Math.addExact(bytes,Files.size(path));}}metrics.set("assembly.physical_bytes_last_observed",bytes);return bytes;}
    private void checkPhysical()throws IOException{if(physicalBytes()>physicalLimit)throw new IOException("assembly physical quota exceeded");}
    private void truncate(FileChannel file,long position)throws IOException{faults.at("recovery-truncate");file.truncate(position);force(file);}
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
    void validateCapacity(long bytes,long reserved)throws IOException{
        long start=metrics.begin("store.capacity");boolean success=false;
        try{if(bytes<0||reserved<0||reserved>maximum||bytes>maximum-reserved)throw new IOException("assembly finalization quota exceeded");success=true;}
        finally{metrics.timed("store.capacity",start,success);}
    }
    private static void write(FileChannel channel,byte[] bytes)throws IOException{
        var buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining())channel.write(buffer);
    }
    boolean failed(){return failed;}
    @Override public void close()throws IOException{try{lock.release();}finally{lockChannel.close();}}

    // Explicit tagged values preserve numeric types (including negative zero) and native Timestamp.
    // ALL maps are represented as pairs so application keys cannot collide with codec tags.
    static Object encode(Object value){
        return S2SAssemblyReader.encode(value);
    }
    static Object decode(Object value){
        return S2SAssemblyReader.decode(value);
    }
    static Map<String,Object> envelope(Object value){return S2SAssemblyReader.envelope(value);}
}
