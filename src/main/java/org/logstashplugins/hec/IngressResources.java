package org.logstashplugins.hec;

import java.util.concurrent.Semaphore;

/**
 * The single set of limits that one {@code splunk_hec} input shares between its HTTP listener and its
 * optional classic TCP listener.
 *
 * <p>Sharing is deliberate: a Logstash pipeline has one queue and one JVM heap, so memory, in-flight
 * work and connection counts must be bounded for the INPUT as a whole. If each listener had its own
 * budget, a burst on one could exhaust the process while the other still believed it had headroom.
 * It also means back-pressure from a slow queue shows up on both listeners (HTTP answers 503, TCP stops
 * reading and lets the sender's TCP window fill).
 */
final class IngressResources implements AutoCloseable{
    /** Aggregate accounting of bytes reserved for in-flight parsing and expansion (max_inflight_bytes). */
    final MemoryBudget memory;
    /**
     * {@code processing}: slots for requests/records being processed right now (max_concurrent_requests).
     * {@code connections}: permits for open sockets, idle ones included (max_connections).
     * {@code emergencyHealth}: one extra permit so a health check can still be answered while the other
     * slots are all busy.
     */
    final Semaphore processing,connections,emergencyHealth=new Semaphore(1);
    /** How much provenance to attach under {@code @metadata.splunk_hec} (hec_metadata option). */
    final MetadataMode metadata;
    /** Immutable startup mapping shared by HTTP and TCP, independent of provenance mode. */
    final S2SMetadataFields metadataFields;
    /** Value-free operator diagnostics (never payload, token or header values); defaults to silent. */
    volatile java.util.function.Consumer<String> diagnostic=message->{};
    private final java.util.concurrent.atomic.AtomicLong lastRejection=new java.util.concurrent.atomic.AtomicLong(),suppressedRejections=new java.util.concurrent.atomic.AtomicLong();
    /**
     * Logs why a request was rejected, at most once per 10 s, with the count of rejections suppressed since the last
     * line. Only the route, status, HEC code, fixed message and the throwing source line are reported.
     */
    void rejected(String route,int status,Throwable cause){
        long now=System.nanoTime(),before=lastRejection.get();
        if(before!=0&&now-before<10_000_000_000L||!lastRejection.compareAndSet(before,now)){suppressedRejections.incrementAndGet();return;}
        long skipped=suppressedRejections.getAndSet(0);
        StackTraceElement[] trace=cause.getStackTrace();
        String where=trace.length>0?trace[0].getClassName().substring(trace[0].getClassName().lastIndexOf('.')+1)+":"+trace[0].getLineNumber():"unknown";
        String reason=cause instanceof HecException e?"HEC code "+e.code+" \""+e.getMessage()+"\"":cause.getClass().getSimpleName();
        diagnostic.accept("HEC request rejected: route="+route+" status="+status+" "+reason+" at "+where+(skipped>0?" ("+skipped+" similar rejections suppressed)":""));
    }
    S2SStreamAssembler assembly;
    String assemblyNamespace="input";
    /** Memory permanently set aside for the health endpoint so it works even when memory is exhausted. */
    private final MemoryBudget.Lease healthReservation;
    /** Create resources with the default, full provenance. */
    IngressResources(Limits limits){this(limits,MetadataMode.FULL);}
    IngressResources(Limits limits,MetadataMode metadata){
        this(limits,metadata,S2SMetadataFields.EMPTY);
    }
    IngressResources(Limits limits,MetadataMode metadata,S2SMetadataFields metadataFields){
        this.metadata=metadata;this.metadataFields=metadataFields;
        memory=new MemoryBudget(limits.aggregate());
        // Fair semaphores hand out slots in arrival order, so no listener or client can be starved.
        processing=new Semaphore(limits.concurrency(),true);connections=new Semaphore(limits.connections(),true);
        healthReservation=memory.lease();healthReservation.charge(256L<<10);
    }
    @Override public void close(){healthReservation.close();}
}
