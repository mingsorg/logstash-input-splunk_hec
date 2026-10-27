package org.logstashplugins.hec;

public record Limits(int concurrency, int connections, int wire, int expanded, long aggregate,
                     int event, int events, int depth, int readMillis, int admissionMillis, int shutdownMillis) {
    public static Limits defaults() {
        return new Limits(16, 64, 10 << 20, 64 << 20, 128L << 20, 1 << 20,
                          10_000, 100, 30_000, 1_000, 10_000);
    }
    public Limits {
        if (concurrency <= 0 || connections < concurrency || wire <= 0 || expanded < wire ||
            aggregate < expanded || aggregate <= (256L << 10) || event <= 0 || event > expanded || events <= 0 || depth <= 0 ||
            readMillis <= 0 || admissionMillis <= 0 || shutdownMillis <= 0)
            throw new IllegalArgumentException("inconsistent positive resource limits");
    }
}
