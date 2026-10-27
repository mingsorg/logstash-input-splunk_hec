package org.logstashplugins.hec;

/** Conservative accounted allocations; every request owns exactly one lease. */
final class MemoryBudget {
    private final long maximum;
    private long used;
    MemoryBudget(long maximum) { this.maximum = maximum; }
    synchronized long used() { return used; }
    Lease lease() { return new Lease(); }
    final class Lease implements AutoCloseable {
        private long bytes;
        private boolean closed;
        void charge(long n) {
            synchronized (MemoryBudget.this) {
                if (Thread.currentThread().isInterrupted() || closed || n < 0 || n > maximum - used) throw HecException.busy();
                bytes += n; used += n;
            }
        }
        @Override public void close() {
            synchronized (MemoryBudget.this) {
                if (!closed) { used -= bytes; bytes = 0; closed = true; }
            }
        }
    }
}
