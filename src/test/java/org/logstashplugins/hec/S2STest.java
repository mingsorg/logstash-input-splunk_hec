package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import java.nio.file.*;

class S2STest {
    /* Synthetic wire builders adapted from reference S2SBodies.java, pinned revision; Apache-2.0.
       Modified to cover native mappings, malformed input and fractional precision. */
    /**
     * Synthetic encoder mirroring S2SDecoder.Reader's primitives. It makes the
     * grammar explicit in tests; captured real UF/HF bodies are exercised below
     * independently, so this encoder is not the interoperability oracle.
     */
    static class Body {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        // Emit low seven-bit groups first, setting bit 7 until the final byte.
        Body v(long v){while((v&~127L)!=0){out.write((int)((v&127)|128));v>>>=7;}out.write((int)v);return this;}
        Body op(int v){out.write(v);return this;}
        // S uses UTF-8 byte length; ns emits the non-null NS form (length + 1).
        // A null NS can be built with v(0), without any following string bytes.
        Body str(String s){byte[] b=s.getBytes(StandardCharsets.UTF_8);v(b.length);out.writeBytes(b);return this;}
        Body ns(String s){byte[] b=s.getBytes(StandardCharsets.UTF_8);v(b.length+1);out.writeBytes(b);return this;}
        Body meta(){return op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::test").ns("channel").v(0);}
        Body csvMeta(){return op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::csv").ns("channel").v(2).str("a.b").str("message");}
        Body event(long flags,int count){return eventAt(flags,count,100,1);}
        // FC/metaId/flags, the conditional four-varint block, then fieldCount.
        // Individual tests append typed fields and payload blob lengths explicitly.
        Body eventAt(long flags,int count,long offset,long sequence){op(0xfc).v(1).v(flags);if((flags&10)!=0)v(7).v(offset).v(sequence).v(1790000000);return v(count);}
        // Finished zlib and unfinished sync-flush exercise both accepted endings.
        byte[] compressed()throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(0xf9);try(DeflaterOutputStream z=new DeflaterOutputStream(b)){z.write(out.toByteArray());}return b.toByteArray();}
        byte[] sync()throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(0xf9);DeflaterOutputStream z=new DeflaterOutputStream(b,new Deflater(),true);z.write(out.toByteArray());z.flush();return b.toByteArray();}
    }
    Limits limits=Limits.defaults();
    List<Map<String,Object>> decode(byte[] bytes)throws Exception{
        return decode(bytes,MetadataMode.FULL,S2SMetadataFields.EMPTY);
    }
    List<Map<String,Object>> decode(byte[] bytes,MetadataMode mode,S2SMetadataFields mapping)throws Exception{
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            var records=new S2SDecoder(limits).decode(bytes,new Compression.Expansion(limits.expanded(),memory),memory);
            var token=new TokenStore(null,"[{\"token\":\""+ProtocolTest.SECRET+"\"}]",s->{}).authenticate("Splunk "+ProtocolTest.SECRET,null);
            return new S2SEvents(limits,new HecProtocol(limits),mode,mapping).map(records,token,Map.of(),bytes,memory);
        }
    }
    @Test void textRecordsEndLinesWithoutIndentMergingOrCrossRequestState()throws Exception{
        Body body=new Body().meta().event(0x23b,0).str("a\n  b").event(0x23b,0).str("c");
        assertEquals(List.of("a","  b","c"),decode(body.compressed()).stream().map(e->e.get("event")).toList());
        assertEquals(3,decode(body.sync()).size());assertTrue(decode(new byte[0]).isEmpty());
        assertTrue(decode(new Body().meta().event(0,0).compressed()).isEmpty());
    }
    @Test void structuredMultilineMultivaluesConflictingNamesAndNanoseconds()throws Exception{
        Body body=new Body().meta().event(0x4a,4)
            .v(7).str("host").str("payload-host")
            .v(7).str("tag").str("first").v(7).str("tag").str("second")
            .v(0x40).v(0).v(246913579).str("first\nsecond"); // .123456789
        Map<String,Object> event=decode(body.compressed()).getFirst();
        assertEquals("first\nsecond",event.get("event"));assertEquals("host",event.get("host"));
        assertEquals("1790000000.123456789",event.get("time"));
        Map<?,?> fields=(Map<?,?>)event.get("fields");assertEquals(List.of("first","second"),fields.get("tag"));assertEquals("payload-host",fields.get("host"));
        assertFalse(event.containsKey("flags"));assertFalse(event.containsKey("message"));assertTrue(event.containsKey("@metadata"));
        assertEquals(event.get("@metadata"),decode(body.compressed()).getFirst().get("@metadata"));
    }
    @Test void multibyteRebatchAndReconnectStableCoordinatesPreserveDistinctOccurrences()throws Exception{
        var together=decode(new Body().meta().eventAt(0x23b,0,100,1).str("é\nrepeat\nrepeat").compressed());
        List<Map<String,Object>> separate=new ArrayList<>();
        separate.addAll(decode(new Body().meta().eventAt(0x23b,0,100,1).str("é").compressed()));
        separate.addAll(decode(new Body().meta().eventAt(0x23b,0,103,1).str("repeat").compressed()));
        separate.addAll(decode(new Body().meta().eventAt(0x23b,0,110,1).str("repeat").compressed()));
        java.util.function.Function<Map<String,Object>,Object> id=e->((Map<?,?>)((Map<?,?>)e.get("@metadata")).get("splunk_hec")).get("id");
        assertEquals(together.stream().map(id).toList(),separate.stream().map(id).toList());
        assertNotEquals(id.apply(together.get(1)),id.apply(together.get(2)));
    }
    @Test void typedMetricAndDimensionsStayNative()throws Exception{
        Body body=new Body().meta().event(0x1004a,2).v(0x13).str("metric_name:cpu").v(0).v(7).str("dimension").str("node");
        byte[] value=ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(1.25).array();
        body.v(8);body.out.writeBytes(value);body.str("raw metric\n");
        var event=decode(body.compressed()).getFirst();Map<?,?> fields=(Map<?,?>)event.get("fields");
        assertEquals(1.25,fields.get("cpu"));assertEquals("node",fields.get("dimension"));assertFalse(event.containsKey("event.kind"));
    }
    @Test void leadingDelimitersRetainAbsolutePositionsAcrossRebatching()throws Exception{
        var together=decode(new Body().meta().eventAt(0x23b,0,100,1).str("\n\r\né\nrepeat").compressed());
        var separate=new ArrayList<Map<String,Object>>();
        separate.addAll(decode(new Body().meta().eventAt(0x23b,0,103,1).str("é").compressed()));
        separate.addAll(decode(new Body().meta().eventAt(0x23b,0,106,1).str("repeat").compressed()));
        java.util.function.Function<Map<String,Object>,Object> id=e->((Map<?,?>)((Map<?,?>)e.get("@metadata")).get("splunk_hec")).get("id");
        assertEquals(together.stream().map(id).toList(),separate.stream().map(id).toList());
    }
    @Test void positionlessRepeatedRecordsUseDistinctBatchScopedIds()throws Exception{
        Body body=new Body().meta();
        for(int i=0;i<2;i++)body.op(0xfc).v(1).v(0x23b).v(0).v(0).v(0).v(1790000000).v(0).str("repeat");
        byte[] bytes=body.compressed();var events=decode(bytes);
        java.util.function.Function<Map<String,Object>,Map<?,?>> meta=e->(Map<?,?>)((Map<?,?>)e.get("@metadata")).get("splunk_hec");
        assertNotEquals(meta.apply(events.get(0)).get("id"),meta.apply(events.get(1)).get("id"));
        assertEquals("identical-batch-retry",((Map<?,?>)meta.apply(events.get(0)).get("s2s")).get("identity_scope"));
        assertEquals(meta.apply(events.get(0)).get("id"),meta.apply(decode(bytes).get(0)).get("id"));
    }
    @Test void csvHeaderProvenanceAndLiteralIndexedNames()throws Exception{
        var event=decode(new Body().csvMeta().event(0x4a,2).v(5).v(0).str("value").v(5).v(1).str("native").str("value,native").compressed()).getFirst();
        assertEquals(Map.of("a.b","value","message","native"),event.get("fields"));
        Map<?,?> s2s=(Map<?,?>)((Map<?,?>)((Map<?,?>)event.get("@metadata")).get("splunk_hec")).get("s2s");
        assertEquals(List.of("a.b","message"),s2s.get("csv_header"));assertFalse(event.containsKey("csv_header"));
    }
    @Test void nativeEpochSecondsDoNotUseHecIntegerUnitHeuristics()throws Exception{
        Body body=new Body().meta().op(0xfc).v(1).v(0x4a).v(7).v(0).v(1).v(17_000_000_000L).v(0).str("future native seconds");
        var event=decode(body.compressed()).getFirst();assertEquals("17000000000",event.get("time"));
        assertEquals(17_000_000_000L,((org.logstash.Timestamp)event.get("@timestamp")).toInstant().getEpochSecond());
        Body fraction=new Body().meta().op(0xfc).v(1).v(0x4a).v(7).v(0).v(1).v(17_000_000_000L)
            .v(1).v(0x40).v(0).v(246913579).str("future native fractional seconds");
        var fractional=decode(fraction.compressed());
        assertEquals(123456789,((org.logstash.Timestamp)fractional.getFirst().get("@timestamp")).toInstant().getNano());
    }
    @Test void strictInvalidBatchNoPartialSalvage()throws Exception{
        Body bad=new Body().meta().event(0x4a,0).str("valid").op(0xfb);
        assertThrows(HecException.class,()->decode(bad.compressed()));
        assertThrows(HecException.class,()->decode(new byte[]{(byte)0xf9,0,1,2}));
        Body ref=new Body().meta().event(0x4a,1).v(15).str("field").v(99).v(1).str("short");
        assertThrows(HecException.class,()->decode(ref.compressed()));
        Body invalid=new Body().meta().event(0x4a,0).v(1).op(0xff);
        assertThrows(HecException.class,()->decode(invalid.compressed()));
        byte[] trailing=Arrays.copyOf(new Body().meta().compressed(),new Body().meta().compressed().length+1);
        assertThrows(HecException.class,()->decode(trailing));
    }
    @Test void gzipCRCAndTrailingGarbageAreValidated()throws Exception{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(GZIPOutputStream z=new GZIPOutputStream(bytes)){z.write("x".getBytes());}
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            assertArrayEquals("x".getBytes(),Compression.gzip(bytes.toByteArray(),new Compression.Expansion(100,memory)));
            byte[] bad=bytes.toByteArray();bad[bad.length-8]^=1;
            assertThrows(HecException.class,()->Compression.gzip(bad,new Compression.Expansion(100,memory)));
            byte[] trailing=Arrays.copyOf(bytes.toByteArray(),bytes.size()+1);
            assertThrows(HecException.class,()->Compression.gzip(trailing,new Compression.Expansion(100,memory)));
        }
    }
    @Test void emptyGzipMembersAreValidAndConcatenateWithoutDroppingPayload()throws Exception{
        ByteArrayOutputStream empty=new ByteArrayOutputStream();try(var gzip=new GZIPOutputStream(empty)){}
        ByteArrayOutputStream payload=new ByteArrayOutputStream();try(var gzip=new GZIPOutputStream(payload)){gzip.write("data".getBytes());}
        ByteArrayOutputStream joined=new ByteArrayOutputStream();joined.writeBytes(empty.toByteArray());joined.writeBytes(payload.toByteArray());joined.writeBytes(empty.toByteArray());
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            assertEquals(0,Compression.gzip(empty.toByteArray(),new Compression.Expansion(100,memory)).length);
            assertArrayEquals("data".getBytes(),Compression.gzip(joined.toByteArray(),new Compression.Expansion(100,memory)));
        }
    }
    @Test void trailingControlMarkerDoesNotConsumeTheDataRecordLimit()throws Exception{
        limits=new Limits(1,4,8192,16384,1<<20,4096,1,10,1000,100,1000);
        assertEquals(1,decode(new Body().meta().event(0x4a,0).str("one").event(0,0).compressed()).size());
    }
    @Test void escapedFieldReferencesMustConsumeTheirEntireSlice()throws Exception{
        String raw="a\"trailing";
        Body body=new Body().meta().event(0x4a,1).v(27).str("field").v(0).v(raw.length()).str(raw);
        assertEquals(6,assertThrows(HecException.class,()->decode(body.compressed())).code);
    }
    @Test void provenanceCountsTowardLogicalSizeAndFieldCopiesCountTowardMemory()throws Exception{
        limits=new Limits(1,4,8192,16384,1<<20,512,10,10,1000,100,1000);
        Body header=new Body().op(0xfe).v(1).ns("source::file").ns("host::host").ns("sourcetype::csv").ns("channel").v(1).str("x".repeat(1000));
        assertEquals(9,assertThrows(HecException.class,()->decode(header.event(0x4a,0).str("small").compressed())).code);
        limits=new Limits(1,4,65536,65536,8<<20,16384,1000,10,1000,100,1000);
        Body amplified=new Body().meta().event(0x23b,1000);
        for(int i=0;i<1000;i++)amplified.v(7).str("field"+i).str("v");
        amplified.str("line\n".repeat(150));
        assertEquals(9,assertThrows(HecException.class,()->decode(amplified.compressed())).code);
    }
    @Test void indexedContentChangesIdentityButFieldOrderDoesNot()throws Exception{
        Body a=new Body().meta().event(0x4a,2).v(7).str("a").str("1").v(7).str("b").str("2").str("same raw");
        Body b=new Body().meta().event(0x4a,2).v(7).str("b").str("2").v(7).str("a").str("1").str("same raw");
        Body c=new Body().meta().event(0x4a,2).v(7).str("a").str("changed").v(7).str("b").str("2").str("same raw");
        java.util.function.Function<List<Map<String,Object>>,Object> id=events->((Map<?,?>)((Map<?,?>)events.getFirst().get("@metadata")).get("splunk_hec")).get("id");
        assertEquals(id.apply(decode(a.compressed())),id.apply(decode(b.compressed())));
        assertNotEquals(id.apply(decode(a.compressed())),id.apply(decode(c.compressed())));
    }
    @Test void amplifiedRawReferencesAreAccountedBeforeCopies()throws Exception{
        Body body=new Body().meta().event(0x4a,200);
        for(int i=0;i<200;i++)body.v(15).str("field"+i).v(0).v(128*1024);
        body.str("x".repeat(128*1024));byte[] compressed=body.compressed();
        assertEquals(9,assertThrows(HecException.class,()->decode(compressed)).code);
    }
    @Test void capturedRealSenderBodiesDecodeAsCompleteBatches()throws Exception{
        int count=0;
        try(var files=Files.list(Path.of("tests/interop/fixtures/senders"))){
            for(Path file:files.filter(p->p.toString().endsWith(".bin")).toList()){
                byte[] bytes=Files.readAllBytes(file);
                assertEquals(TokenStore.fingerprint(bytes)+".bin",file.getFileName().toString(),"captured fixture digest mismatch");
                boolean oversized;
                try(var memory=new MemoryBudget(limits.aggregate()).lease()){
                    var records=new S2SDecoder(limits).decode(bytes,new Compression.Expansion(limits.expanded(),memory),memory);
                    oversized=records.stream().anyMatch(r->HecProtocol.lines(HecProtocol.utf8(r.raw())).stream().anyMatch(line->line.getBytes(StandardCharsets.UTF_8).length>limits.event()));
                }
                if(oversized){
                    assertEquals(9,assertThrows(HecException.class,()->decode(bytes)).code);
                }else{var events=decode(bytes);count+=events.size();}
            }
        }
        assertTrue(count>0,"no captured real sender events exercised");
    }
    @Test void selectedMetadataIsExactStringTypedNamespacedAndIndependentOfProvenance()throws Exception{
        byte[] bytes=new Body().meta().event(0x23b,6)
            .v(4).str("custom_tenant").str("acme")
            .v(4).str("number").str("001")
            .v(4).str("unselected").str("secret")
            .v(7).str("host").str("indexed-host")
            .v(3).str("number").v(42)
            .v(11).str("boolean").v(62).str("first\nsecond").compressed();
        var mapping=S2SMetadataFields.parse("{\"custom_tenant\":\"host\",\"number\":\"tenant\",\"missing\":\"absent\",\"CUSTOM_TENANT\":\"case_sensitive\",\"channel\":\"not_handshake\",\"boolean\":\"not_indexed\"}");
        for(MetadataMode mode:MetadataMode.values()){
            var original=decode(bytes,mode,S2SMetadataFields.EMPTY);
            assertEquals(original,decode(bytes,mode,S2SMetadataFields.parse("{}")));
            var mapped=decode(bytes,mode,mapping);assertEquals(2,mapped.size());
            for(int i=0;i<2;i++){
                var event=new LinkedHashMap<>(mapped.get(i));
                assertEquals(Map.of("host","acme","tenant","001"),event.remove("s2s_metadata"));
                assertEquals(original.get(i),event,"mapping must preserve payload/time/indexed fields and IDs");
                assertEquals("host",event.get("host"));
                assertEquals(Map.of("host","indexed-host","number",42L,"boolean",true),event.get("fields"));
            }
            assertNotSame(mapped.get(0).get("s2s_metadata"),mapped.get(1).get("s2s_metadata"));
        }
        assertFalse(decode(bytes,MetadataMode.NONE,S2SMetadataFields.parse("{\"absent\":\"missing\"}")).getFirst().containsKey("s2s_metadata"));
        // Changing only per-record metadata does not enter coordinate-based IDs.
        var changed=new Body().meta().event(0x4a,1).v(4).str("custom_tenant").str("changed").str("same").compressed();
        var prior=new Body().meta().event(0x4a,1).v(4).str("custom_tenant").str("acme").str("same").compressed();
        java.util.function.Function<Map<String,Object>,Object> id=e->((Map<?,?>)((Map<?,?>)e.get("@metadata")).get("splunk_hec")).get("id");
        assertEquals(id.apply(decode(prior).getFirst()),id.apply(decode(changed).getFirst()));
    }
    @Test void selectedMetadataCountsTowardLogicalCapAndCopiesAreReservedBeforeAllocation()throws Exception{
        limits=new Limits(1,4,8192,16384,1<<20,512,10,10,1000,100,1000);
        var mapping=S2SMetadataFields.parse("{\"extra\":\"tenant\"}");
        byte[] bytes=new Body().meta().event(0x4a,1).v(4).str("extra").str("x".repeat(512)).str("small").compressed();
        assertEquals(1,decode(bytes,MetadataMode.NONE,S2SMetadataFields.EMPTY).size());
        assertEquals(9,assertThrows(HecException.class,()->decode(bytes,MetadataMode.NONE,mapping)).code);
        // Failed reservation cannot leave a partially materialized namespace.
        Map<String,Object> envelope=new LinkedHashMap<>();MemoryBudget budget=new MemoryBudget(100);
        try(var memory=budget.lease()){
            assertEquals(9,assertThrows(HecException.class,()->mapping.select(Map.of("extra","value"),memory)).code);
            assertTrue(envelope.isEmpty());assertEquals(0,budget.used());
        }
        try(var selectionMemory=new MemoryBudget(4096).lease()){
            var selected=mapping.select(Map.of("extra","value"),selectionMemory);
            try(var memory=budget.lease()){
                assertEquals(9,assertThrows(HecException.class,()->selected.apply(envelope,memory)).code);
                assertTrue(envelope.isEmpty());assertEquals(0,budget.used());
            }
        }
        limits=new Limits(1,4,65536,65536,8<<20,16384,1000,10,1000,100,1000);
        Body amplified=new Body().meta().event(0x23b,300);
        StringBuilder policy=new StringBuilder("{");
        for(int i=0;i<300;i++){
            amplified.v(4).str("k"+i).str("v");
            if(i>0)policy.append(',');policy.append('"').append("k").append(i).append("\":\"d").append(i).append('"');
        }
        var many=S2SMetadataFields.parse(policy.append('}').toString());
        byte[] multiline=amplified.str("line\n".repeat(150)).compressed();
        assertEquals(150,decode(multiline,MetadataMode.NONE,S2SMetadataFields.EMPTY).size());
        assertEquals(9,assertThrows(HecException.class,()->decode(multiline,MetadataMode.NONE,many)).code);
    }
    @Test void selectedLogicalSizeAcceptsTheExactCapAndRejectsOneByteLess()throws Exception{
        var mapping=S2SMetadataFields.parse("{\"extra\":\"tenant\"}");
        byte[] bytes=new Body().meta().event(0x4a,1).v(4).str("extra").str("é\"\\".repeat(64)).str("small").compressed();
        var event=new LinkedHashMap<>(decode(bytes,MetadataMode.NONE,mapping).getFirst());event.remove("@timestamp");
        int size=HecProtocol.JSON.writeValueAsBytes(event).length;
        limits=new Limits(1,4,8192,16384,1<<20,size,10,10,1000,100,1000);
        assertEquals(1,decode(bytes,MetadataMode.NONE,mapping).size());
        limits=new Limits(1,4,8192,16384,1<<20,size-1,10,10,1000,100,1000);
        assertEquals(9,assertThrows(HecException.class,()->decode(bytes,MetadataMode.NONE,mapping)).code);
    }
    @Test void mappingAloneExceedsTheCapEvenWithFullProvenance()throws Exception{
        var mapping=S2SMetadataFields.parse("{\"extra\":\"tenant\"}");
        byte[] bytes=new Body().meta().event(0x4a,1).v(4).str("extra").str("x".repeat(2500)).str("small").compressed();
        for(MetadataMode mode:MetadataMode.values()){
            limits=new Limits(1,4,8192,16384,1<<20,mode==MetadataMode.FULL?4096:2048,10,10,1000,100,1000);
            assertEquals(1,decode(bytes,mode,S2SMetadataFields.EMPTY).size(),"unmapped control must fit in "+mode);
            assertEquals(9,assertThrows(HecException.class,()->decode(bytes,mode,mapping)).code);
        }
    }
}
