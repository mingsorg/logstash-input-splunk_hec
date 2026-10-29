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
    /** Memory permanently set aside for the health endpoint so it works even when memory is exhausted. */
    private final MemoryBudget.Lease healthReservation;
    /** Create resources with the default, full provenance. */
    IngressResources(Limits limits){this(limits,MetadataMode.FULL);}
    IngressResources(Limits limits,MetadataMode metadata){
        this.metadata=metadata;
        memory=new MemoryBudget(limits.aggregate());
        // Fair semaphores hand out slots in arrival order, so no listener or client can be starved.
        processing=new Semaphore(limits.concurrency(),true);connections=new Semaphore(limits.connections(),true);
        healthReservation=memory.lease();healthReservation.charge(256L<<10);
    }
    @Override public void close(){healthReservation.close();}
}
