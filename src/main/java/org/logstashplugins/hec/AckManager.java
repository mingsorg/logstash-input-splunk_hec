package org.logstashplugins.hec;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.function.LongSupplier;

/** All state transitions, duplicate polls and consume-on-true run under this monitor. */
public final class AckManager implements AutoCloseable {
    static final long MAX_ID = 9_007_199_254_740_991L;
    private record Key(String token, String channel) {}
    private static final class Channel {
        final Map<Long, Boolean> ids = new HashMap<>();
        long touched; int pins; boolean cleanup; long idle;
    }
    public record Ticket(String token, String channel, long id) {}
    private final Map<Key, Channel> channels = new HashMap<>();
    private final int maxChannels, perChannel, global;
    private final LongSupplier clock;
    private final FileChannel counter;
    private final FileLock lock;
    private final Path state;
    private long next, high;
    private int outstanding;

    public AckManager(Path directory) throws IOException { this(directory, 1000, 10_000, 100_000, System::nanoTime); }
    AckManager(Path directory, int maxChannels, int perChannel, int global, LongSupplier clock) throws IOException {
        if (maxChannels <= 0 || perChannel <= 0 || global <= 0) throw new IllegalArgumentException("positive ACK limits required");
        this.maxChannels = maxChannels; this.perChannel = perChannel; this.global = global; this.clock = clock;
        Files.createDirectories(directory);
        state = directory.resolve("ack-high-water-v1");
        counter = FileChannel.open(directory.resolve("ack.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired;
        try{acquired=counter.tryLock();}
        catch(RuntimeException e){counter.close();throw new IOException("ACK state already owned",e);}
        lock = acquired;
        if (lock == null) { counter.close(); throw new IOException("ACK state already owned"); }
        try{
            if (!Files.exists(state)) { next = high = 0; persist(0); }
            else {
                if(Files.size(state)!=8)throw new IOException("invalid ACK high-water state");
                byte[] bytes=Files.readAllBytes(state);
                if(bytes.length!=8)throw new IOException("invalid ACK high-water state");
                next = high = ByteBuffer.wrap(bytes).getLong();
                if (high < 0 || high > MAX_ID) throw new IOException("invalid ACK high-water value");
            }
        }catch(IOException|RuntimeException error){
            try{close();}catch(IOException closing){error.addSuppressed(closing);}throw error;
        }
    }
    private void persist(long value) throws IOException {
        Path temp=Files.createTempFile(state.getParent(),".ack-",".tmp");
        try {
            if(Files.getFileStore(temp).supportsFileAttributeView("posix"))
                Files.setPosixFilePermissions(temp,PosixFilePermissions.fromString("rw-------"));
            try(FileChannel output=FileChannel.open(temp,StandardOpenOption.WRITE)){
                ByteBuffer b=ByteBuffer.allocate(8).putLong(value);b.flip();
                while(b.hasRemaining())output.write(b);output.force(true);
            }
            Files.move(temp,state,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            try(FileChannel directory=FileChannel.open(state.getParent(),StandardOpenOption.READ)){directory.force(true);}
        }finally{Files.deleteIfExists(temp);}
    }
    public synchronized Ticket reserve(TokenStore.Token token, String channel) {
        cleanup();
        Key key = new Key(token.identity(), channel);
        Channel c = channels.get(key);
        if (outstanding >= global || (c == null && channels.size() >= maxChannels) ||
            (c != null && c.ids.size() >= perChannel)) throw HecException.busy();
        if (next == high) {
            if (high > MAX_ID - 1024) throw HecException.busy();
            try { persist(high + 1024); high += 1024; }
            catch (IOException e) { throw HecException.busy(); }
        }
        if (c == null) { c = new Channel(); channels.put(key, c); }
        c.cleanup = token.idleCleanup(); c.idle = token.idleNanos(); c.touched = clock.getAsLong();
        long id = next++;
        c.ids.put(id, false); c.pins++; outstanding++;
        return new Ticket(token.identity(), channel, id);
    }
    public synchronized void finish(Ticket ticket, boolean success) {
        Channel c = channels.get(new Key(ticket.token, ticket.channel));
        if (c == null) throw new IllegalStateException("pinned ACK channel disappeared");
        c.pins--; c.touched = clock.getAsLong();
        if (success) c.ids.put(ticket.id, true);
        else if (c.ids.remove(ticket.id) != null) outstanding--;
    }
    public synchronized Map<String, Boolean> poll(TokenStore.Token token, String channel, List<Long> ids) {
        cleanup();
        Channel c = channels.get(new Key(token.identity(), channel));
        Map<String, Boolean> result = new LinkedHashMap<>();
        // Oracle collapses duplicates before consuming; last duplicate must not overwrite true.
        for (long id : new LinkedHashSet<>(ids)) {
            boolean complete = c != null && Boolean.TRUE.equals(c.ids.get(id));
            result.put(Long.toString(id), complete);
            if (complete) { c.ids.remove(id); outstanding--; }
        }
        if (c != null) { c.touched = clock.getAsLong(); c.cleanup = token.idleCleanup(); c.idle = token.idleNanos(); }
        return result;
    }
    private void cleanup() {
        long now = clock.getAsLong();
        channels.values().removeIf(c -> {
            if (c.pins == 0 && c.cleanup && now - c.touched >= c.idle) {
                outstanding -= c.ids.size(); return true;
            }
            return false;
        });
    }
    @Override public synchronized void close() throws IOException {
        try { lock.release(); } finally { counter.close(); }
    }
}
