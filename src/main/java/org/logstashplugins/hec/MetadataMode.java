package org.logstashplugins.hec;

import java.util.Locale;

/**
 * How much S2S provenance is attached under {@code @metadata.splunk_hec}.
 * {@code @metadata} never reaches outputs unless a filter copies it, so this
 * controls cost and size accounting, not the visible event body. The Logstash
 * core fields {@code @timestamp} and {@code @version} are unaffected.
 */
enum MetadataMode {
    /** Event identity, wire provenance and (TCP) connection provenance. */
    FULL,
    /** Only the stable event identity, enough for idempotent outputs. */
    ID_ONLY,
    /** No {@code @metadata} at all. */
    NONE;

    static MetadataMode parse(String text){
        return switch(text.strip().toLowerCase(Locale.ROOT)){
            case "full"->FULL;
            case "id_only"->ID_ONLY;
            case "none"->NONE;
            default->throw new IllegalArgumentException("hec_metadata must be full, id_only or none");
        };
    }
}
