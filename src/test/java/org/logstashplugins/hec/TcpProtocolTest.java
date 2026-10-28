package org.logstashplugins.hec;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

class TcpProtocolTest {
    final Limits limits=new Limits(16,64,10<<20,64<<20,512L<<20,8<<20,10000,100,30000,1000,10000);

    static final class Fragmented extends ByteArrayInputStream{
        Fragmented(byte[] bytes){super(bytes);}
        @Override public synchronized int read(byte[] bytes,int offset,int length){return super.read(bytes,offset,Math.min(113,length));}
    }
    @Test void realLatestUfHfPlainAndCompressedStreamsMatchTheirOracleRecords()throws Exception{
        int checked=0;
        for(String manifest:List.of("manifest.json","manifest-compressed.json")){
            Path fixtures=Path.of("tests/tcp/fixtures");
            for(var sample:HecProtocol.JSON.readTree(Files.readAllBytes(fixtures.resolve(manifest)))){
                byte[] wire=Files.readAllBytes(fixtures.resolve(sample.path("client").asText()));
                assertEquals(sample.path("client").asText().substring(0,64),TokenStore.fingerprint(wire));
                MemoryBudget budget=new MemoryBudget(limits.aggregate());List<Map<String,Object>> source=new ArrayList<>();List<Long> ids=new ArrayList<>();
                try(var connection=budget.lease();var capabilityMemory=budget.lease();var infoMemory=budget.lease()){
                    connection.charge(256L<<10);
                    InputStream input=new Fragmented(wire);
                    var greeting=S2STcpProtocol.greeting(input);assertEquals(sample.path("hostname").asText(),greeting.hostname());
                    var caps=S2STcpProtocol.frame(input,limits,capabilityMemory);
                    var info=S2STcpProtocol.frame(input,limits,infoMemory);
                    boolean compressed=sample.path("compressed").asBoolean();
                    assertEquals(compressed,caps.compressed());assertEquals(compressed,info.compressed());
                    assertTrue(S2STcpProtocol.capability(caps.pairs().get("__s2s_capabilities"),"ack"));
                    assertTrue(S2STcpProtocol.capability(info.pairs().get("__s2s_capabilities"),"v4"));
                    if(compressed){assertEquals(0xf9,input.read());input=new S2STcpProtocol.Inflated(input);}
                    var policy=new TokenStore.Token("tcp-test",false,Map.of("index","main","host",greeting.hostname()),Set.of(),false,false,false,600_000_000_000L);
                    HecProtocol protocol=new HecProtocol(limits);
                    try(var session=new S2SDecoder(limits).new StreamSession();InputStream records=input){
                        int opcode;
                        while((opcode=records.read())>=0){
                            var memory=budget.lease();boolean retained=false;
                            try{
                                var record=session.read(opcode,records,memory);retained=record.retainsLease();
                                if(record.eventId()!=null)ids.add(record.eventId());
                                if(record.event()!=null&&!record.event().control()){
                                    var maps=new S2SEvents(limits,protocol).mapWithIdentity(List.of(record.event()),policy,Map.of(),record.wireSha256(),memory);
                                    for(var event:maps)if(String.valueOf(event.get("source")).startsWith("/tmp/hec-source."))source.add(event);
                                }
                            }finally{if(!retained)memory.close();}
                        }
                    }
                }
                assertEquals(0,budget.used(),"connection/session allocations must release");
                List<Long> expectedIds=new ArrayList<>();for(var id:sample.path("ids"))expectedIds.add(id.longValue());assertEquals(expectedIds,ids);
                List<String> expectedValues=new ArrayList<>();
                for(var event:sample.path("source_records")){
                    String raw=event.path("raw").asText();if(raw.isEmpty())continue;
                    long flags=Long.parseLong(event.path("flags").asText().substring(2),16);
                    List<String> values=(flags&0x40)!=0?List.of(raw):HecProtocol.lines(raw);
                    for(String value:values)expectedValues.add(event.path("source").asText()+"\0"+event.path("host").asText()+"\0"+event.path("sourcetype").asText()+"\0"+event.path("index").asText()+"\0"+value);
                }
                assertEquals(expectedValues,source.stream().map(e->e.get("source")+"\0"+e.get("host")+"\0"+e.get("sourcetype")+"\0"+e.get("index")+"\0"+e.get("event")).toList());
                assertTrue(sample.path("positive_ids_acknowledged").asBoolean());checked++;
            }
        }
        assertEquals(6,checked,"both captured UF connections plus HF in each compression mode");
    }
    @Test void ackEncodingUsesUnsignedVarintsAndNeverAnInclusiveGapRange()throws Exception{
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        S2STcpProtocol.ack(output,300);assertArrayEquals(new byte[]{(byte)0xfb,(byte)0xac,2},output.toByteArray());
        output.reset();S2STcpProtocol.ack(output,-1);
        assertEquals("fbffffffffffffffffff01",HexFormat.of().formatHex(output.toByteArray()));
    }
    @Test void recordMetadataOverridesChannelDefaultsWithoutConflatingIndexedHost()throws Exception{
        MemoryBudget budget=new MemoryBudget(limits.aggregate());
        try(var session=new S2SDecoder(limits).new StreamSession()){
            byte[] metadata=new S2STest.Body().meta().out.toByteArray();var retained=budget.lease();
            assertTrue(session.read(0xfe,new ByteArrayInputStream(metadata,1,metadata.length-1),retained).retainsLease());
            byte[] event=new S2STest.Body().op(0xfc).v(1).v(0x20d).v(0).v(1790000000).v(4)
                .v(4).str("MetaData:Source").str("source::fwd-hb")
                .v(4).str("MetaData:Sourcetype").str("sourcetype::fwd-hb")
                .v(4).str("MetaData:Host").str("host::$decideOnStartup")
                .v(7).str("host").str("payload-host").str("HB").out.toByteArray();
            try(var memory=budget.lease()){
                var record=session.read(0xfc,new ByteArrayInputStream(event,1,event.length-1),memory);
                assertEquals(0L,record.eventId());assertEquals("fwd-hb",record.event().source());assertEquals("fwd-hb",record.event().sourcetype());
                assertNull(record.event().host());assertEquals("payload-host",record.event().fields().get("host"));
            }
        }
        assertEquals(0,budget.used());
    }
    @Test void incompleteRecordDoesNotEscapeAsAnAcceptedEventAndMetadataReplacementsRelease()throws Exception{
        MemoryBudget budget=new MemoryBudget(limits.aggregate());
        try(var session=new S2SDecoder(limits).new StreamSession()){
            long retained=-1;
            for(int i=0;i<20;i++){
                byte[] metadata=new S2STest.Body().meta().out.toByteArray();var memory=budget.lease();
                var parsed=session.read(metadata[0]&255,new ByteArrayInputStream(metadata,1,metadata.length-1),memory);
                assertTrue(parsed.retainsLease());
                if(retained<0)retained=budget.used();else assertEquals(retained,budget.used());
            }
            S2STest.Body record=new S2STest.Body().op(0xfc).v(1).v(0x3f).v(7).v(100).v(0).v(2).v(1790000000).v(0).str("complete");
            byte[] bytes=record.out.toByteArray();
            try(var memory=budget.lease()){
                assertThrows(UncheckedIOException.class,()->session.read(bytes[0]&255,new ByteArrayInputStream(bytes,1,bytes.length-2),memory));
            }
        }
        assertEquals(0,budget.used());
    }
    @Test void compressedTailMustFinishOrHaveAValidSyncFlushBoundary()throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();Deflater deflater=new Deflater();
        DeflaterOutputStream zipper=new DeflaterOutputStream(out,deflater,true);zipper.write("records".getBytes());zipper.flush();
        byte[] valid=out.toByteArray();
        try(var input=new S2STcpProtocol.Inflated(new Fragmented(valid))){assertArrayEquals("records".getBytes(),input.readAllBytes());}
        byte[] shortTail=Arrays.copyOf(valid,valid.length-1);
        try(var input=new S2STcpProtocol.Inflated(new Fragmented(shortTail))){assertThrows(IOException.class,input::readAllBytes);}
        deflater.end();
    }
    @Test void handshakeFramesAreBoundedAndRequireTheirStringTrailer()throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();S2STcpProtocol.writeFrame(out,Map.of("__s2s_capabilities","ack=1;compression=0"));
        try(var memory=new MemoryBudget(limits.aggregate()).lease()){
            var frame=S2STcpProtocol.frame(new Fragmented(out.toByteArray()),limits,memory);
            assertFalse(frame.compressed());assertEquals("ack=1;compression=0",frame.pairs().get("__s2s_capabilities"));
            byte[] invalid=out.toByteArray();invalid[invalid.length-1]=1;
            assertThrows(IOException.class,()->S2STcpProtocol.frame(new Fragmented(invalid),limits,memory));
            assertThrows(IOException.class,()->S2STcpProtocol.frame(new ByteArrayInputStream(new byte[]{127,-1,-1,-1}),limits,memory));
        }
    }
}
