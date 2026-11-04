package org.logstashplugins.hec;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/** Single-writer atomic, checksummed snapshot journal. No Java object deserialization. */
final class S2SAssemblyStore implements AutoCloseable {
    private final Path directory,state,next;
    private final long maximum;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private boolean failed;
    S2SAssemblyStore(Path directory,long maximum)throws IOException{
        this.directory=directory;this.maximum=maximum;
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
    byte[] recover()throws IOException{
        if(Files.exists(next,LinkOption.NOFOLLOW_LINKS)&&(!Files.isRegularFile(next,LinkOption.NOFOLLOW_LINKS)||Files.size(next)>maximum+65))
            throw new IOException("invalid uncommitted assembly snapshot size/type");
        if(!Files.exists(state,LinkOption.NOFOLLOW_LINKS))return null;
        if(!Files.isRegularFile(state,LinkOption.NOFOLLOW_LINKS)||Files.size(state)>maximum+65)throw new IOException("invalid assembly snapshot size/type");
        byte[] bytes=Files.readAllBytes(state);
        if(bytes.length<65||bytes[64]!='\n')throw new IOException("corrupt assembly snapshot");
        byte[] payload=Arrays.copyOfRange(bytes,65,bytes.length);
        if(!TokenStore.fingerprint(payload).equals(new String(bytes,0,64,StandardCharsets.US_ASCII)))throw new IOException("assembly checksum mismatch");
        return payload;
    }
    void commit(Object value)throws IOException{
        if(failed)throw new IOException("assembly storage is blocked");
        // Bounded serialization; a quota failure occurs BEFORE touching the committed snapshot.
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        HecProtocol.JSON.writeValue(new FilterOutputStream(output){
            private long count;
            @Override public void write(int b)throws IOException{if(++count>maximum)throw new IOException("assembly quota exceeded");out.write(b);}
            @Override public void write(byte[] b,int off,int n)throws IOException{if(n>maximum-count)throw new IOException("assembly quota exceeded");count+=n;out.write(b,off,n);}
        },value);
        byte[] payload=output.toByteArray();
        try{
            // A torn 'next' is never a commit. Replace it only after validating committed state.
            try(FileChannel file=FileChannel.open(next,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){
                Files.setPosixFilePermissions(next,PosixFilePermissions.fromString("rw-------"));
                write(file,(TokenStore.fingerprint(payload)+"\n").getBytes(StandardCharsets.US_ASCII));write(file,payload);file.force(true);
            }
            Files.move(next,state,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            try(FileChannel dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}
        }catch(IOException error){failed=true;throw new IOException("assembly commit failed; storage blocked",error);}
    }
    /** Count the actual JSON bytes without retaining another serialized snapshot. */
    long serializedSize(Object value)throws IOException{
        class Counter extends OutputStream{
            long count;
            @Override public void write(int b)throws IOException{add(1);}
            @Override public void write(byte[] b,int off,int n)throws IOException{add(n);}
            private void add(int n)throws IOException{
                if(n>maximum-count)throw new IOException("assembly quota exceeded");
                count+=n;
            }
        }
        var counter=new Counter();HecProtocol.JSON.writeValue(counter,value);return counter.count;
    }
    void validateCapacity(Object value,long reserved)throws IOException{
        if(reserved>maximum||serializedSize(value)>maximum-reserved)throw new IOException("assembly finalization quota exceeded");
    }
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
        if(!(value instanceof Map<?,?> map))return value;
        if(map.containsKey("map")){
            Map<String,Object> result=new LinkedHashMap<>();
            for(Object item:(List<?>)map.get("map")){var pair=(List<?>)item;result.put((String)pair.get(0),decode(pair.get(1)));}return result;
        }
        if(map.containsKey("list"))return ((List<?>)map.get("list")).stream().map(S2SAssemblyStore::decode).toList();
        if(map.containsKey("timestamp"))return new org.logstash.Timestamp(java.time.Instant.parse((String)map.get("timestamp")));
        var pair=(List<?>)map.get("number");String text=(String)pair.get(1);
        return switch((String)pair.get(0)){
            case "Long" -> Long.valueOf(text);case "Integer" -> Integer.valueOf(text);case "Double" -> Double.valueOf(text);
            case "BigInteger" -> new java.math.BigInteger(text);case "BigDecimal" -> new java.math.BigDecimal(text);
            default -> throw new IllegalArgumentException("invalid assembly numeric type");
        };
    }
    @SuppressWarnings("unchecked") static Map<String,Object> envelope(Object value){return (Map<String,Object>)decode(value);}
}
