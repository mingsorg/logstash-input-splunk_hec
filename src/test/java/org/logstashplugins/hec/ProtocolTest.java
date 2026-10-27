package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.*;
import java.util.*;
import org.logstash.Timestamp;

class ProtocolTest {
    @TempDir Path temp;
    static final String SECRET="11111111-1111-4111-8111-111111111111";
    static final String INLINE="[{\"token\":\""+SECRET+"\",\"indexes\":\"main\"}]";
    final Limits limits=Limits.defaults();
    final HecProtocol protocol=new HecProtocol(limits);
    TokenStore.Token token()throws Exception{return new TokenStore(null,INLINE,s->{}).authenticate("Splunk "+SECRET,null);}
    HecProtocol.Prepared parse(String body)throws Exception{
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            return protocol.events(body.getBytes(StandardCharsets.UTF_8),token(),Map.of(),memory);
        }
    }
    @Test void envelopesAndLosslessNumbers()throws Exception{
        var parsed=parse("{\"event\":{\"message\":\"native\",\"a.b\":[1,2.5,null,true]},\"time\":\"1700000000.123456789\"}");
        assertNull(parsed.failure());var event=parsed.events().getFirst();
        assertFalse(event.containsKey("message"));assertFalse(event.containsKey("host"));
        assertEquals("1700000000.123456789",event.get("time"));
        assertEquals(123456789,((Timestamp)event.get("@timestamp")).toInstant().getNano());
        Map<?,?> value=(Map<?,?>)event.get("event");assertEquals("native",value.get("message"));
        assertEquals(Arrays.asList(1L,2.5,null,true),value.get("a.b"));
        assertEquals(Long.MAX_VALUE,parse("{\"event\":9223372036854775807}").events().getFirst().get("event"));
        assertEquals(new BigInteger("9223372036854775808"),parse("{\"event\":9223372036854775808}").events().getFirst().get("event"));
        assertEquals(new BigDecimal("0.1"),parse("{\"event\":0.1}").events().getFirst().get("event"));
        assertEquals(new BigDecimal("123.45678901234567890123456789"),parse("{\"event\":123.45678901234567890123456789}").events().getFirst().get("event"));
        assertEquals(6,parse("{\"event\":1e1000000000}").failure().code);
        assertEquals(0.5,parse("{\"event\":0.5}").events().getFirst().get("event"));
        assertEquals(Double.doubleToRawLongBits(-0.0),Double.doubleToRawLongBits((Double)parse("{\"event\":-0.0}").events().getFirst().get("event")));
    }
    @Test void prefixArraysDuplicateKeysAndOracleErrors()throws Exception{
        assertEquals(2,parse("[{\"event\":1},{\"event\":2}]").events().size());
        var batch=parse("{\"event\":\"one\"}{\"host\":\"missing\"}{\"event\":\"three\"}");
        assertEquals(1,batch.events().size());assertEquals(12,batch.failure().code);assertEquals(1,batch.failure().event);
        var trailing=parse("{\"event\":\"one\"}junk");assertEquals(1,trailing.events().size());assertEquals(1,trailing.failure().event);
        assertEquals("second",parse("{\"event\":\"first\",\"event\":\"second\"}").events().getFirst().get("event"));
        assertEquals(15,parse("{\"event\":\"x\",\"fields\":{\"a\":{\"b\":1}}}").failure().code);
        assertEquals(7,parse("{\"event\":1,\"index\":\"other\"}").failure().code);
        assertEquals(13,parse("{\"event\":\"  \"}").failure().code);
        for(String value:List.of("true","false","null"))assertEquals(6,parse("{\"event\":"+value+"}").failure().code);
        assertEquals(5,parse(" ").failure().code);
    }
    @Test void rawIsStrictRequestLocalAndWhitespacePreserving()throws Exception{
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            var raw=protocol.raw("one\r\n\ntwo\n \ntail\r".getBytes(StandardCharsets.UTF_8),token(),Map.of(),memory);
            assertEquals(List.of("one","two"," ","tail\r"),raw.events().stream().map(e->e.get("event")).toList());
            assertEquals(List.of("new"),protocol.raw("new".getBytes(),token(),Map.of(),memory).events().stream().map(e->e.get("event")).toList());
            assertThrows(HecException.class,()->protocol.raw(new byte[]{(byte)0xff},token(),Map.of(),memory));
        }
    }
    @Test void timeUnitsAndPrecision(){
        for(String time:List.of("1700000000.125","1700000000125","1700000000125000","1700000000125000000"))
            assertEquals("2023-11-14T22:13:20.125Z",HecProtocol.timestamp(time).toString());
        assertEquals("1969-12-31T23:59:59.500Z",HecProtocol.timestamp("-0.5").toString());
        assertThrows(HecException.class,()->HecProtocol.timestamp("1700000000.0000000001"));
        assertThrows(HecException.class,()->HecProtocol.timestamp("1e1000000000"));
    }
    @Test void policyReloadSnapshotsRevocationAndIndexPrecedence()throws Exception{
        Path file=temp.resolve("inputs.conf");Files.writeString(file,"[http]\nindex = main\n[http://one]\ntoken = "+SECRET+"\nindexes = main, permitted\n");
        List<String> diagnostics=new ArrayList<>();TokenStore store=new TokenStore(file,"[]",diagnostics::add);
        var original=store.authenticate("Splunk "+SECRET,null);
        assertEquals("permitted",protocol.finalizeEnvelope(Map.of("event","x"),original,Map.of("index","permitted"),new MemoryBudget(limits.aggregate()).lease()).get("index"));
        Files.writeString(file,"[http://partial]\ntoken =\n");assertFalse(store.reload());
        assertEquals(original.identity(),store.authenticate("Splunk "+SECRET,null).identity());
        Files.writeString(file,"[http]\nmaxIdleTime = 0\n");assertFalse(store.reload());
        assertEquals(original.identity(),store.authenticate("Splunk "+SECRET,null).identity(),"invalid empty policy must not revoke working tokens");
        Files.writeString(file,"[http]\n");assertTrue(store.reload());
        assertThrows(HecException.class,()->store.authenticate("Splunk "+SECRET,null));
        assertEquals("main",original.defaults().get("index"));
        Files.writeString(file,"[http://renamed]\ntoken = "+SECRET+"\n");assertTrue(store.reload());
        assertEquals(original.identity(),store.authenticate("Splunk "+SECRET,null).identity());
        assertTrue(diagnostics.stream().noneMatch(s->s.contains(SECRET)));
        assertThrows(IllegalArgumentException.class,()->new TokenStore(file,INLINE,s->{}));
    }
    @Test void basicQueryAndDisabledAuthentication()throws Exception{
        TokenStore store=new TokenStore(null,INLINE,s->{});
        String basic=Base64.getEncoder().encodeToString(("u:"+SECRET).getBytes());
        assertEquals(token().identity(),store.authenticate("Basic "+basic,null).identity());
        assertEquals(16,assertThrows(HecException.class,()->store.authenticate(null,SECRET)).code);
        assertEquals(3,assertThrows(HecException.class,()->store.authenticate("Basic @@@",null)).code);
        assertEquals(2,assertThrows(HecException.class,()->store.authenticate(null,null)).code);
        Path disabled=temp.resolve("disabled.conf");Files.writeString(disabled,"[http]\ndisabled = true\n[http://one]\ntoken = "+SECRET+"\ndisabled = false\n");
        TokenStore globallyDisabled=new TokenStore(disabled,"[]",s->{});
        assertEquals(1,assertThrows(HecException.class,()->globallyDisabled.authenticate("Splunk "+SECRET,null)).code);
        var invalid=assertThrows(IllegalArgumentException.class,()->new TokenStore(null,"credential-must-not-appear",s->{}));
        assertFalse(invalid.toString().contains("credential-must-not-appear"));
    }
    @Test void protectedRootNamesRejectButNestedLiteralNamesSurvive()throws Exception{
        for(String name:List.of("@timestamp","@metadata","@version")){
            var rejected=parse("{\"event\":\"x\",\""+name+"\":\"source\"}");
            assertEquals(6,rejected.failure().code);assertTrue(rejected.events().isEmpty());
            var accepted=parse("{\"event\":{\""+name+"\":\"payload\"},\"fields\":{\""+name+"\":\"indexed\"}}");
            assertNull(accepted.failure());
            assertEquals("payload",((Map<?,?>)accepted.events().getFirst().get("event")).get(name));
            assertEquals("indexed",((Map<?,?>)accepted.events().getFirst().get("fields")).get(name));
        }
    }
    @Test void malformedPolicyCannotRevokeTokensOrTurnAnAllowlistIntoAllowAll()throws Exception{
        Path file=temp.resolve("policy.conf");
        Files.writeString(file,"[http://active]\ntoken = "+SECRET+"\nindexes = main\n");
        TokenStore store=new TokenStore(file,"[]",s->{});
        for(String candidate:List.of("# policy update still being written\n","[monitor://unrelated]\n",
            "[http://active]\ntoken = "+SECRET+"\nindexes = ,,\n",
            "[http://active]\ntoken = "+SECRET+"\nindexes = main,\n")){
            Files.writeString(file,candidate);assertFalse(store.reload());
            assertEquals(Set.of("main"),store.authenticate("Splunk "+SECRET,null).indexes());
        }
        Files.writeString(file,"[http]\n");assertTrue(store.reload());
        assertThrows(HecException.class,()->store.authenticate("Splunk "+SECRET,null));
    }
    @Test void aggregateAccountingAndLimits(){
        MemoryBudget budget=new MemoryBudget(100);
        try(var a=budget.lease();var b=budget.lease()){
            a.charge(60);b.charge(40);assertThrows(HecException.class,()->b.charge(1));assertEquals(100,budget.used());
        }assertEquals(0,budget.used());
        assertThrows(IllegalArgumentException.class,()->new Limits(0,64,10,64,128,1,10,10,1,1,1));
    }
    @Test void malformedUnicodeDepthAndLogicalEventLimitFailBeforeQueue()throws Exception{
        assertEquals(6,parse("{\"event\":\"\\ud800\"}").failure().code);
        String deep="{\"event\":"+"[".repeat(101)+"0"+"]".repeat(101)+"}";
        assertEquals(6,parse(deep).failure().code);
        assertThrows(HecException.class,()->parse("{\"event\":\""+"x".repeat(limits.event())+"\"}"));
        byte[] prefix="{\"event\":\"valid\"}".getBytes(StandardCharsets.UTF_8);
        byte[] invalid=Arrays.copyOf(prefix,prefix.length+1);invalid[invalid.length-1]=(byte)0xff;
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            var prepared=protocol.events(invalid,token(),Map.of(),memory);
            assertEquals(1,prepared.events().size());assertEquals(6,prepared.failure().code);assertEquals(1,prepared.failure().event);
        }
    }
}
