package org.logstashplugins.hec;

import java.util.LinkedHashMap;
import java.util.Map;

final class HecException extends RuntimeException {
    final int status, code;
    final Integer event;
    HecException(int status, int code, String text) { this(status, code, text, null); }
    HecException(int status, int code, String text, Integer event) {
        super(text, null, false, true); this.status = status; this.code = code; this.event = event;
    }
    Map<String, Object> response() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("text", getMessage()); out.put("code", code);
        if (event != null) out.put("invalid-event-number", event);
        return out;
    }
    static HecException invalid() { return new HecException(400, 6, "Invalid data format"); }
    static HecException busy() { return new HecException(503, 9, "Server is busy"); }
}
