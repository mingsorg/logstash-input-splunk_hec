package org.logstashplugins.hec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public final class TokenStore {
    private static final Set<String> GLOBAL = Set.of("disabled", "index", "host", "source", "sourcetype",
        "useACK", "allowQueryStringAuth", "ackIdleCleanup", "maxIdleTime");
    private static final Set<String> TOKEN = new HashSet<>(GLOBAL);
    static { TOKEN.addAll(Set.of("token", "indexes")); }
    public record Token(String identity, boolean disabled, Map<String, String> defaults,
                        Set<String> indexes, boolean ack, boolean queryAuth, boolean idleCleanup, long idleNanos) {}
    private record Snapshot(Map<String, Token> tokens, boolean disabled) {}
    private final AtomicReference<Snapshot> current = new AtomicReference<>();
    private final Path file;
    private final String inline;
    private final Consumer<String> diagnostics;

    public TokenStore(Path file, String inline, Consumer<String> diagnostics) throws IOException {
        this.file = file; this.inline = inline; this.diagnostics = diagnostics;
        try{current.set(load());}
        catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalArgumentException("invalid inline token JSON");}
        catch(NumberFormatException e){throw new IllegalArgumentException("invalid maxIdleTime");}
    }
    public boolean reload() {
        try { current.set(load()); return true; }
        catch (Exception e) { diagnostics.accept("token reload rejected; retaining last good configuration (" + e.getClass().getSimpleName() + ")"); return false; }
    }
    public Token authenticate(String header, String queryToken) {
        Snapshot snapshot = current.get();
        String secret = queryToken;
        boolean query = secret != null;
        if (!query) {
            if (header == null || header.isBlank()) throw new HecException(401, 2, "Token is required");
            if (header.startsWith("Splunk ")) secret = header.substring(7);
            else if (header.startsWith("Basic ")) {
                try {
                    String basic = HecProtocol.utf8(Base64.getDecoder().decode(header.substring(6)));
                    int colon = basic.indexOf(':');
                    if (colon < 0) throw new IllegalArgumentException();
                    secret = basic.substring(colon + 1);
                } catch (Exception e) { throw new HecException(401, 3, "Invalid authorization"); }
            } else throw new HecException(401, 3, "Invalid authorization");
        }
        Token token = snapshot.tokens.get(fingerprint(secret));
        if (token == null) throw new HecException(403, 4, "Invalid token");
        if (snapshot.disabled || token.disabled) throw new HecException(403, 1, "Token disabled");
        if (query && !token.queryAuth) throw new HecException(400, 16, "Query string authorization is not enabled");
        return token;
    }
    private Snapshot load() throws IOException {
        Map<String, String> global = new LinkedHashMap<>();
        Map<String, Map<String, String>> stanzas = new LinkedHashMap<>();
        boolean recognized = false;
        if (file != null) {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            if(text.isBlank()||!text.endsWith("\n"))throw new IllegalArgumentException("incomplete inputs.conf replacement");
            Map<String, String> scope = null;
            for (String raw : text.split("\\R", -1)) {
                String line = raw.strip();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    String name = line.substring(1, line.length()-1);
                    if (name.equals("http")) { scope = global; recognized = true; }
                    else if (name.startsWith("http://")) {
                        recognized = true;
                        scope = new LinkedHashMap<>();
                        if (stanzas.putIfAbsent(name, scope) != null) throw new IllegalArgumentException("duplicate token stanza");
                    } else { diagnostics.accept("unsupported inputs.conf stanza"); scope = null; }
                } else {
                    int eq = line.indexOf('=');
                    if (eq <= 0 || scope == null) throw new IllegalArgumentException("invalid inputs.conf syntax");
                    String key = line.substring(0, eq).strip();
                    if (!(scope == global ? GLOBAL : TOKEN).contains(key)) {
                        // Never echo a value, a token stanza name, or an untrusted unknown key.
                        diagnostics.accept("unknown inputs.conf key " + (key.matches("[A-Za-z][A-Za-z0-9_.]{0,63}")?key:"(name SHA-256 " + fingerprint(key) + ")"));
                        continue;
                    }
                    if (scope.putIfAbsent(key, line.substring(eq+1).strip()) != null)
                        throw new IllegalArgumentException("duplicate inputs.conf key " + key);
                }
            }
            if (!recognized) throw new IllegalArgumentException("missing HTTP policy stanza");
        }
        List<Map<String, String>> definitions = new ArrayList<>(stanzas.values());
        List<Map<String, Object>> imported = new ObjectMapper().readValue(inline, new TypeReference<>() {});
        for (Map<String, Object> item : imported) {
            Map<String, String> definition = new LinkedHashMap<>();
            for (var entry : item.entrySet()) {
                if (!TOKEN.contains(entry.getKey())) throw new IllegalArgumentException("unknown inline token key");
                if (entry.getValue() == null) throw new IllegalArgumentException("null token setting");
                if(entry.getValue() instanceof Map<?,?>||entry.getValue() instanceof List<?>)throw new IllegalArgumentException("token settings must be scalar");
                if(Set.of("token","index","indexes","host","source","sourcetype").contains(entry.getKey())&&!(entry.getValue() instanceof String))
                    throw new IllegalArgumentException("string token metadata required");
                definition.put(entry.getKey(), entry.getValue().toString());
            }
            definitions.add(definition);
        }
        Map<String, Token> tokens = new HashMap<>();
        for (Map<String, String> local : definitions) {
            String secret = local.get("token");
            if (secret == null || secret.isBlank()) throw new IllegalArgumentException("token identity required");
            Map<String, String> merged = new HashMap<>(global); merged.putAll(local);
            Map<String, String> defaults = new HashMap<>();
            defaults.put("index", "main");
            for (String key : List.of("index", "host", "source", "sourcetype")) {
                if (merged.containsKey(key)) defaults.put(key, merged.get(key));
            }
            Set<String> allowed = new HashSet<>();
            if (merged.containsKey("indexes")) for (String index : merged.get("indexes").split(",", -1)) {
                if (index.isBlank()) throw new IllegalArgumentException("empty allowed index");
                allowed.add(index.strip());
            }
            long idle = idleNanos(merged);
            String identity = fingerprint(secret);
            Token token = new Token(identity, bool(local, "disabled", false), Map.copyOf(defaults), Set.copyOf(allowed),
                bool(merged, "useACK", false), bool(merged, "allowQueryStringAuth", false),
                bool(merged, "ackIdleCleanup", false), idle);
            if (tokens.putIfAbsent(identity, token) != null) throw new IllegalArgumentException("duplicate token identity");
        }
        // Validate global switches even in an intentionally empty configuration.
        for (String k : List.of("useACK", "allowQueryStringAuth", "ackIdleCleanup")) bool(global, k, false);
        idleNanos(global);
        return new Snapshot(Map.copyOf(tokens), bool(global, "disabled", false));
    }
    private static long idleNanos(Map<String,String> settings) {
        long seconds = Long.parseLong(settings.getOrDefault("maxIdleTime", "600"));
        if (seconds <= 0 || seconds > Long.MAX_VALUE / 1_000_000_000L)
            throw new IllegalArgumentException("invalid maxIdleTime");
        return seconds * 1_000_000_000L;
    }
    private static boolean bool(Map<String, String> map, String key, boolean fallback) {
        if (!map.containsKey(key)) return fallback;
        return switch (map.get(key).toLowerCase(Locale.ROOT)) {
            case "true", "1" -> true;
            case "false", "0" -> false;
            default -> throw new IllegalArgumentException("invalid boolean " + key);
        };
    }
    static String fingerprint(String text) {
        return fingerprint(text.getBytes(StandardCharsets.UTF_8));
    }
    static String fingerprint(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
}
