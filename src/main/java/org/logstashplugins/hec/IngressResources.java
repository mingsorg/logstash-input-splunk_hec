package org.logstashplugins.hec;

import java.util.concurrent.Semaphore;

/** One input-wide budget/admission policy shared by HTTP and optional TCP. */
final class IngressResources implements AutoCloseable{
    final MemoryBudget memory;
    final Semaphore processing,connections,emergencyHealth=new Semaphore(1);
    private final MemoryBudget.Lease healthReservation;
    IngressResources(Limits limits){
        memory=new MemoryBudget(limits.aggregate());
        processing=new Semaphore(limits.concurrency(),true);connections=new Semaphore(limits.connections(),true);
        healthReservation=memory.lease();healthReservation.charge(256L<<10);
    }
    @Override public void close(){healthReservation.close();}
}
