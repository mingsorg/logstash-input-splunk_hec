package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class S2SAssemblyRecoveryTest {
    @TempDir Path temporary;
    S2SAssemblyInspectorTest fixture;
    Path root;
    @BeforeEach void setup()throws Exception{
        root=temporary.toRealPath();Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));
        fixture=new S2SAssemblyInspectorTest();fixture.temporary=root;fixture.setup();
    }
    S2SAssemblyInspectorTest.Cli cli(S2SAssemblyInspector.Faults faults,String... args){
        var out=new ByteArrayOutputStream();var err=new ByteArrayOutputStream();
        int status=S2SAssemblyRecovery.run(args,new PrintStream(out),new PrintStream(err),faults);
        return new S2SAssemblyInspectorTest.Cli(status,out.toString(),err.toString());
    }
    S2SAssemblyInspectorTest.Cli cli(String... args){return cli(S2SAssemblyInspector.NO_FAULTS,args);}
    Path export(Path source,String name,int status)throws Exception{
        var before=fixture.inventory(source);Path archive=root.resolve(name);
        var result=cli("export","--assembly-directory",source.toString(),"--output",archive.toString(),"--json");
        assertEquals(status,result.status(),result.stderr());assertEquals(before,fixture.inventory(source));
        assertFalse(result.stdout().contains("private-"));assertEquals("not_evaluated",HecProtocol.JSON.readTree(result.stdout()).get("restart_compatibility").asText());
        assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(archive));fixture.released(source);return archive;
    }
    Path rebuild(Path archive,String name,int status)throws Exception{
        byte[] before=Files.readAllBytes(archive);Path target=root.resolve(name);
        var result=cli("rebuild","--archive",archive.toString(),"--assembly-directory",target.toString(),"--json");
        assertEquals(status,result.status(),result.stderr());assertArrayEquals(before,Files.readAllBytes(archive));
        assertEquals(PosixFilePermissions.fromString("rwx------"),Files.getPosixFilePermissions(target));
        try(var files=Files.list(target)){for(Path file:files.toList())assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(file));}
        return target;
    }
    S2SStreamAssembler.State recoveredCopy(Path source,String name)throws Exception{
        Path copy=root.resolve(name);S2SJournalTest.copy(source,copy);return fixture.fixture.recovered(copy,1L<<20);
    }
    void same(S2SStreamAssembler.State expected,S2SStreamAssembler.State actual)throws Exception{
        assertEquals(HecProtocol.JSON.readTree(HecProtocol.JSON.writeValueAsBytes(expected)),HecProtocol.JSON.readTree(HecProtocol.JSON.writeValueAsBytes(actual)));
        assertEquals(new ArrayList<>(expected.pending().keySet()),new ArrayList<>(actual.pending().keySet()));
        assertEquals(new ArrayList<>(expected.receipts().keySet()),new ArrayList<>(actual.receipts().keySet()));
        assertEquals(expected.outbox().stream().map(S2SStreamAssembler.Output::id).toList(),actual.outbox().stream().map(S2SStreamAssembler.Output::id).toList());
    }
    Path legacy(String name,S2SStreamAssembler.State state)throws Exception{
        Path path=root.resolve(name);Files.createDirectory(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.write(path.resolve("lock"),new byte[0]);Files.write(path.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(state)));return path;
    }
    S2SAssemblyRecovery.Origin original(){return new S2SAssemblyRecovery.Origin(new S2SAssemblyRecovery.Source("v2","original_v2",null,null,null),new S2SAssemblyRecovery.Completeness("complete",null),null);}
    S2SAssemblyRecovery.Origin published(String classification,S2SAssemblyRecovery.Range range,S2SAssemblyRecovery.Origin previous){
        return new S2SAssemblyRecovery.Origin(new S2SAssemblyRecovery.Source("v3","published_v3",1L,0L,1L),new S2SAssemblyRecovery.Completeness(classification,range),previous);
    }
    byte[] archive(S2SStreamAssembler.State state,S2SAssemblyRecovery.Origin origin)throws Exception{
        var payload=new S2SAssemblyRecovery.Payload(origin,state);byte[] covered=HecProtocol.JSON.writeValueAsBytes(payload);
        return HecProtocol.JSON.writeValueAsBytes(new S2SAssemblyRecovery.Archive(1,covered.length,TokenStore.fingerprint(covered),payload));
    }
    void refusedArchive(String name,byte[] bytes,int status)throws Exception{
        Path input=root.resolve(name+".archive"),target=root.resolve(name+"-target");Files.write(input,bytes);
        var result=cli("rebuild","--archive",input.toString(),"--assembly-directory",target.toString(),"--json");
        assertEquals(status,result.status(),result.stderr());assertEquals("",result.stdout());assertFalse(Files.exists(target));
        assertArrayEquals(bytes,Files.readAllBytes(input));
    }
    S2SStreamAssembler.State simple(Object value){
        return new S2SStreamAssembler.State("configuration",new LinkedHashMap<>(),List.of(new S2SStreamAssembler.Output("output",Map.of("map",List.of(Arrays.asList("value",value))),"sender")),new LinkedHashMap<>(),false);
    }
    int tokens(byte[] bytes)throws Exception{int n=0;try(var parser=HecProtocol.JSON.createParser(bytes)){while(parser.nextToken()!=null)n++;}return n;}
    @Test void actualArchiveDepthAndTokenBoundariesArePreflightedBeforeOutputClaim()throws Exception{
        for(int levels:List.of(28,29)){
            Object value="leaf";for(int i=0;i<levels;i++)value=Map.of("list",List.of(value));
            var state=simple(value);Path source=legacy("depth-"+levels,state);assertEquals(0,S2SAssemblyInspector.inspect(source).status());
            if(levels==28){Path saved=export(source,"depth-ok.archive",0);S2SAssemblyRecovery.readArchive(Files.readAllBytes(saved));}
            else refusesExport(source,"depth-refused.archive",5);
        }
        int overhead=tokens(HecProtocol.JSON.writeValueAsBytes(simple(Map.of("list",List.of()))));
        for(int headroom:List.of(100,0)){
            var state=simple(Map.of("list",Collections.nCopies(S2SAssemblyInspector.MAX_TOKENS-overhead-headroom,null)));
            assertEquals(S2SAssemblyInspector.MAX_TOKENS-headroom,tokens(HecProtocol.JSON.writeValueAsBytes(state)));
            Path source=legacy("tokens-"+headroom,state);assertEquals(0,S2SAssemblyInspector.inspect(source).status());
            if(headroom==100){Path saved=export(source,"tokens-ok.archive",0);S2SAssemblyRecovery.readArchive(Files.readAllBytes(saved));}
            else refusesExport(source,"tokens-refused.archive",5);
        }
    }
    @Test void checksumValidContradictoryProvenanceRangesAndHistoryRefuseBeforeClaim()throws Exception{
        var state=simple(null);var prefix=published("incomplete_prefix",new S2SAssemblyRecovery.Range(0,1),null);
        var cases=new ArrayList<S2SAssemblyRecovery.Origin>();
        cases.add(published("complete",new S2SAssemblyRecovery.Range(0,1),null));
        cases.add(published("incomplete_prefix",null,null));cases.add(published("complete",null,prefix));
        for(var range:List.of(new S2SAssemblyRecovery.Range(-1,1),new S2SAssemblyRecovery.Range(0,0),new S2SAssemblyRecovery.Range(Long.MAX_VALUE,1),
                new S2SAssemblyRecovery.Range(S2SAssemblyReader.HISTORY,1),new S2SAssemblyRecovery.Range(1,S2SAssemblyReader.HISTORY)))cases.add(published("incomplete_prefix",range,null));
        cases.add(new S2SAssemblyRecovery.Origin(original().source(),prefix.completeness(),null));
        cases.add(new S2SAssemblyRecovery.Origin(original().source(),original().completeness(),published("complete",null,null)));
        cases.add(new S2SAssemblyRecovery.Origin(new S2SAssemblyRecovery.Source("v3","original_v2",1L,0L,1L),original().completeness(),null));
        cases.add(new S2SAssemblyRecovery.Origin(new S2SAssemblyRecovery.Source("v3","published_v3",1L,2L,1L),original().completeness(),null));
        cases.add(new S2SAssemblyRecovery.Origin(new S2SAssemblyRecovery.Source("v2","original_v2",1L,null,null),original().completeness(),null));
        cases.add(published("complete",null,cases.getFirst()));
        int n=0;for(var origin:cases)refusedArchive("contradictory-"+n++,archive(state,origin),3);
    }
    @Test void validHistoryAtLimitRoundTripsAndExhaustionIsBudgetNotCorruption()throws Exception{
        var origin=original();for(int i=0;i<S2SAssemblyRecovery.MAX_HISTORY;i++)origin=published("complete",null,origin);
        byte[] allowed=archive(simple(null),origin);S2SAssemblyRecovery.readArchive(allowed);
        Path input=root.resolve("history.archive");Files.write(input,allowed);rebuild(input,"history-target",0);
        refusedArchive("history-exhausted",archive(simple(null),published("complete",null,origin)),5);
    }
    @Test void archiveStringsRefusePrimitiveCoercionEvenWithTheCoercedCanonicalChecksum()throws Exception{
        var base=recoveredCopy(fixture.seed("coercion-seed"),"coercion-reference");int n=0;
        for(String text:List.of("123","true","1.5"))for(String field:List.of("sender","configuration","id")){
            var state=new S2SStreamAssembler.State(field.equals("configuration")?text:base.configuration(),base.pending(),
                List.of(new S2SStreamAssembler.Output(field.equals("id")?text:"id",base.outbox().getFirst().envelope(),field.equals("sender")?text:"sender")),base.receipts(),false);
            byte[] valid=archive(state,original());S2SAssemblyRecovery.readArchive(valid);
            var node=(com.fasterxml.jackson.databind.node.ObjectNode)HecProtocol.JSON.readTree(valid);
            var owner=(com.fasterxml.jackson.databind.node.ObjectNode)node.at(field.equals("configuration")?"/payload/state":"/payload/state/outbox/0");owner.set(field,HecProtocol.JSON.readTree(text));
            refusedArchive("coercion-"+n++,HecProtocol.JSON.writeValueAsBytes(node),3);
        }
        var canonical=(com.fasterxml.jackson.databind.node.ObjectNode)HecProtocol.JSON.valueToTree(base);
        String pending=base.pending().keySet().iterator().next(),fingerprint="9".repeat(64);
        ((com.fasterxml.jackson.databind.node.ObjectNode)canonical.at("/pending/"+pending)).put("rule",fingerprint);
        var state=S2SStreamAssembler.recoveryMapper(1L<<20).treeToValue(canonical,S2SStreamAssembler.State.class);
        var node=(com.fasterxml.jackson.databind.node.ObjectNode)HecProtocol.JSON.readTree(archive(state,original()));
        ((com.fasterxml.jackson.databind.node.ObjectNode)node.at("/payload/state/pending/"+pending)).set("rule",HecProtocol.JSON.readTree(fingerprint));
        refusedArchive("fingerprint-coercion",HecProtocol.JSON.writeValueAsBytes(node),3);
        for(String field:List.of("format","authority"))for(String value:List.of("123","true","1.5")){
            node=(com.fasterxml.jackson.databind.node.ObjectNode)HecProtocol.JSON.readTree(archive(base,original()));
            ((com.fasterxml.jackson.databind.node.ObjectNode)node.at("/payload/origin/source")).set(field,HecProtocol.JSON.readTree(value));
            byte[] covered=HecProtocol.JSON.writeValueAsBytes(node.get("payload"));node.put("byte_count",covered.length);node.put("sha256",TokenStore.fingerprint(covered));
            refusedArchive("origin-coercion-"+n++,HecProtocol.JSON.writeValueAsBytes(node),3);
        }
    }
    @Test void boundMetadataCannotBeDeletedOrSubstitutedAndSurvivesWriterCompaction()throws Exception{
        Path source=fixture.seed("binding-source");Files.write(S2SAssemblyTest.journal(source),new byte[]{1},StandardOpenOption.APPEND);
        Path target=rebuild(export(source,"binding.archive",2),"binding-target",2);
        Path other=rebuild(export(fixture.seed("binding-other"),"other.archive",0),"other-target",0);
        byte[] originalMetadata=Files.readAllBytes(target.resolve("recovery-origin-v1"));
        for(boolean compacted:List.of(false,true)){
            if(compacted)try(var store=new S2SAssemblyStore(target,1L<<20)){
                var state=S2SStreamAssembler.recoveryMapper(1L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);store.initialize(state);store.compact();
            }
            var pointer=S2SAssemblyReader.pointer(S2SAssemblyReader.checked(Files.readAllBytes(target.resolve("current-v3"))),S2SStreamAssembler.recoveryMapper(4096));
            var snapshot=S2SAssemblyReader.snapshot(S2SAssemblyReader.checked(Files.readAllBytes(target.resolve("snapshot-v3-"+pointer.generation()))),pointer,S2SStreamAssembler.recoveryMapper(1L<<20));
            assertEquals(TokenStore.fingerprint(originalMetadata),snapshot.recoveryOrigin());assertEquals(2,S2SAssemblyInspector.inspect(target).status());
            for(boolean substitute:List.of(false,true)){
                Path bad=root.resolve("binding-bad-"+compacted+"-"+substitute);S2SJournalTest.copy(target,bad);
                Files.setPosixFilePermissions(bad,PosixFilePermissions.fromString("rwx------"));
                if(substitute)Files.write(bad.resolve("recovery-origin-v1"),Files.readAllBytes(other.resolve("recovery-origin-v1")));else Files.delete(bad.resolve("recovery-origin-v1"));
                var error=assertThrows(S2SAssemblyInspector.Refusal.class,()->S2SAssemblyInspector.inspect(bad));assertEquals(3,error.status);
                try(var store=new S2SAssemblyStore(bad,1L<<20)){assertThrows(IOException.class,store::recover);}
                assertThrows(IOException.class,()->fixture.fixture.assembler(bad,1L<<20,p->{}));
            }
        }
        Path ordinary=fixture.seed("ordinary");var state=recoveredCopy(ordinary,"ordinary-reference");
        assertEquals("{\"sequence\":7,\"state\":"+HecProtocol.JSON.writeValueAsString(state)+"}",HecProtocol.JSON.writeValueAsString(new S2SAssemblyStore.Snapshot(7,state)));
        try(var store=new S2SAssemblyStore(ordinary,1L<<20)){var retained=S2SStreamAssembler.recoveryMapper(1L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);store.initialize(retained);store.compact();}
        assertFalse(Files.readString(ordinary.resolve("snapshot-v3-2")).contains("recoveryOrigin"));
    }
    @Test void compatibleRebuiltAssemblerContinuesDrainsAndSuppressesRetriesWithStableIds()throws Exception{
        Path source=fixture.seed("adopt-source"),target=rebuild(export(source,"adopt.archive",0),"adopt-target",0);
        var before=recoveredCopy(target,"adopt-reference");var clock=new java.util.concurrent.atomic.AtomicLong(1000);var received=new LinkedBlockingQueue<Map<String,Object>>();
        try(var assembly=new S2SStreamAssembler(target,S2SLineBreakerPolicy.parse(S2SAssemblyTest.RULES),MetadataMode.FULL,S2SMetadataFields.EMPTY,"{}",1L<<20,10,fixture.fixture.memory,s->{},clock::get)){
            fixture.fixture.accept(assembly,0,"START private-payload\nSTART private-tail");same(before,(S2SStreamAssembler.State)HttpTlsTest.privateField(assembly,"state"));
            long offset=before.pending().values().iterator().next().offset();fixture.fixture.accept(assembly,offset,"continued");
            clock.set(1101);try(var lease=fixture.fixture.memory.lease()){assembly.expire(lease);}
            var completed=(S2SStreamAssembler.State)HttpTlsTest.privateField(assembly,"state");assertEquals(2,completed.outbox().size());
            assertEquals(before.outbox().getFirst().id(),completed.outbox().getFirst().id());
            assertEquals(completed.outbox().getFirst().sender(),completed.outbox().getLast().sender());
            var expected=completed.outbox().stream().map(output->S2SAssemblyReader.envelope(output.envelope())).toList();assembly.start(received::add);
            assertEquals(expected.getFirst(),received.poll(5,TimeUnit.SECONDS));assertEquals(expected.getLast(),received.poll(5,TimeUnit.SECONDS));
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(assembly.outputCount()!=0&&System.nanoTime()<deadline)Thread.sleep(10);assertEquals(0,assembly.outputCount());
            fixture.fixture.accept(assembly,0,"START private-payload\nSTART private-tail");fixture.fixture.accept(assembly,offset,"continued");
            assertEquals(0,assembly.pendingCount());assertEquals(0,assembly.outputCount());assertTrue(received.isEmpty());
        }
        assertNotNull(S2SAssemblyInspector.inspect(target).summary().get("recovery_origin"));
    }
    @Test void interopAdoptionProbeRunsCompatibleCopyAndPreservesParentAckAndTlsFixtures()throws Exception{
        Path probes=root.resolve("probe-classes");Files.createDirectory(probes);
        var compiler=javax.tools.ToolProvider.getSystemJavaCompiler();assertNotNull(compiler);
        assertEquals(0,compiler.run(null,null,null,"--release","21","-classpath",fixture.classpath(),"-d",probes.toString(),
            "tests/interop/JournalProbe.java","tests/interop/RecoveryProbe.java"));
        Path source=root.resolve("probe-source"),ack=root.resolve("ack-high-water"),tls=root.resolve("tls-identity");
        Files.writeString(ack,"123456");Files.writeString(tls,"identity-retained");
        String cp=probes+File.pathSeparator+fixture.classpath();
        Process seed=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",cp,"org.logstashplugins.hec.JournalProbe","seed",source.toString()).start();
        try{assertTrue(seed.waitFor(30,TimeUnit.SECONDS));assertEquals(0,seed.exitValue(),new String(seed.getErrorStream().readAllBytes()));}finally{S2SAssemblyInspectorTest.cleanup(seed);}
        Path target=rebuild(export(source,"probe.archive",0),"probe-rebuilt",0),copy=root.resolve("probe-adoption-copy");S2SJournalTest.copy(target,copy);
        Process adoption=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",cp,"org.logstashplugins.hec.RecoveryProbe","adopt",copy.toString()).start();
        try{
            assertTrue(adoption.waitFor(30,TimeUnit.SECONDS));assertEquals(0,adoption.exitValue(),new String(adoption.getErrorStream().readAllBytes()));
            var proof=HecProtocol.JSON.readTree(adoption.getInputStream().readAllBytes());
            for(String field:List.of("compatible_adoption","continuation","drained","preserved_ids","sender_order","retry_suppression"))assertTrue(proof.get(field).booleanValue(),field);
            assertEquals(proof.at("/original_ids/0"),proof.at("/finalized_ids/0"));
        }finally{S2SAssemblyInspectorTest.cleanup(adoption);}
        assertEquals("123456",Files.readString(ack));assertEquals("identity-retained",Files.readString(tls));
    }
    @Test void publishedAndOriginalLegacyPreserveStateAndFreshCoordinates()throws Exception{
        Path source=fixture.seed("source");var expected=recoveredCopy(source,"reference");
        for(Path path:List.of(source,legacy("legacy",expected))){
            Path archive=export(path,path.getFileName()+".archive",0);var saved=S2SAssemblyRecovery.readArchive(Files.readAllBytes(archive));
            same(expected,saved.payload().state());Path rebuilt=rebuild(archive,path.getFileName()+"-rebuilt",0);
            same(expected,recoveredCopy(rebuilt,path.getFileName()+"-copy"));
            var summary=S2SAssemblyInspector.inspect(rebuilt).summary();assertEquals(0L,summary.get("sequence"));assertEquals(1L,summary.get("generation"));
            assertEquals("published_v3",summary.get("authority"));assertEquals(1,summary.get("pending"));assertEquals(1,summary.get("outbox"));
            assertFalse(Files.exists(rebuilt.resolve("backup-v2")));assertFalse(Files.exists(rebuilt.resolve("recovery-incomplete")));
        }
    }
    @Test void nativeTypesTimesMapReceiptPendingAndOutputOrderRemainLosslessWhileBlocked()throws Exception{
        var base=recoveredCopy(fixture.seed("native-seed"),"native-reference");
        var nativeValues=new LinkedHashMap<String,Object>();nativeValues.put("negative-zero",-0.0d);nativeValues.put("decimal",new java.math.BigDecimal("123.45000"));
        nativeValues.put("large",new java.math.BigInteger("123456789012345678901234567890"));nativeValues.put("integer",7);nativeValues.put("long",9L);
        nativeValues.put("timestamp",new org.logstash.Timestamp(java.time.Instant.parse("2023-11-14T22:13:20.123456789Z")));nativeValues.put("null",null);nativeValues.put("list",Arrays.asList(true,"private-value",null));
        var outputs=new ArrayList<S2SStreamAssembler.Output>();for(int i=0;i<3;i++)outputs.add(new S2SStreamAssembler.Output(UUID.randomUUID().toString(),S2SAssemblyReader.encode(nativeValues),"sender-"+i));
        var pending=new LinkedHashMap<>(base.pending());pending.put("b".repeat(64),pending.values().iterator().next());
        var receipts=new LinkedHashMap<String,String>();receipts.put("b".repeat(64),"a".repeat(64));receipts.put("a".repeat(64),"b".repeat(64));
        var expected=new S2SStreamAssembler.State("incompatible-preserved-fingerprint",pending,outputs,receipts,true);
        Path archive=export(legacy("typed",expected),"typed.archive",0);Path target=rebuild(archive,"typed-rebuilt",0);
        var actual=recoveredCopy(target,"typed-recovered");same(expected,actual);assertTrue(actual.blocked());assertEquals(expected.configuration(),actual.configuration());
        var decoded=S2SAssemblyReader.envelope(actual.outbox().getFirst().envelope());
        for(String key:List.of("negative-zero","decimal","large","integer","long","timestamp"))assertEquals(nativeValues.get(key).getClass(),decoded.get(key).getClass());
        assertEquals(Double.doubleToRawLongBits(-0.0),Double.doubleToRawLongBits((Double)decoded.get("negative-zero")));
        assertEquals(new java.math.BigDecimal("123.45000"),decoded.get("decimal"));assertEquals(nativeValues.get("timestamp"),decoded.get("timestamp"));
        Path copy=root.resolve("incompatible-activation");S2SJournalTest.copy(target,copy);assertThrows(IOException.class,()->fixture.fixture.assembler(copy,1L<<20,p->{}));
    }
    @Test void tornHeadersAndAuthenticatedPayloadPropagateOmissionsAcrossRebuildAndReexport()throws Exception{
        Path source=fixture.seed("prefix");var expected=recoveredCopy(source,"prefix-reference");
        long prefix=Files.size(S2SAssemblyTest.journal(source));
        var tx=new S2SAssemblyStore.Transaction(expected.configuration(),List.of(),List.of(),List.of(),List.of(),List.of(),Map.of(),null,null,true);
        S2SAssemblyInspectorTest.append(source,2,HecProtocol.JSON.writeValueAsBytes(tx));byte[] complete=Files.readAllBytes(S2SAssemblyTest.journal(source));
        int[] lengths={1,17,87,88,89,complete.length-(int)prefix-1};
        for(int length:lengths){
            Files.write(S2SAssemblyTest.journal(source),Arrays.copyOf(complete,(int)prefix+length));
            Path archive=export(source,"prefix-"+length+".archive",2);var first=S2SAssemblyRecovery.readArchive(Files.readAllBytes(archive));same(expected,first.payload().state());
            assertEquals(new S2SAssemblyRecovery.Range(prefix,length),first.payload().origin().completeness().omitted_range());
            Path target=rebuild(archive,"prefix-rebuilt-"+length,2);same(expected,recoveredCopy(target,"prefix-copy-"+length));
            assertEquals(2,S2SAssemblyInspector.inspect(target).status());
            Path again=export(target,"prefix-again-"+length+".archive",2);var second=S2SAssemblyRecovery.readArchive(Files.readAllBytes(again));
            assertEquals(first.payload().origin(),second.payload().origin().previous());same(expected,second.payload().state());
        }
    }
    @Test void completeCorruptionMissingAuthorityAndCandidatesNeverFallBack()throws Exception{
        Path source=fixture.seed("corruption");var expected=recoveredCopy(source,"corrupt-reference");
        Files.write(source.resolve("backup-v2"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(expected)));
        byte[] bytes=Files.readAllBytes(S2SAssemblyTest.journal(source));
        for(int offset:new int[]{0,4,8,24,56,bytes.length-1}){
            byte[] bad=bytes.clone();bad[offset]^=1;Files.write(S2SAssemblyTest.journal(source),bad);refusesExport(source,"bad-"+offset,3);
        }
        Files.write(S2SAssemblyTest.journal(source),bytes);Files.delete(source.resolve("current-v3"));refusesExport(source,"no-pointer",3);
    }
    void refusesExport(Path source,String name,int status)throws Exception{
        var before=fixture.inventory(source);Path output=root.resolve(name);
        var result=cli("export","--assembly-directory",source.toString(),"--output",output.toString(),"--json");
        assertEquals(status,result.status(),result.stderr());assertEquals("",result.stdout());assertFalse(result.stderr().contains("private-"));
        assertFalse(Files.exists(output));assertEquals(before,fixture.inventory(source));
    }
    @Test void archiveTamperingUnknownDuplicateMissingTrailingAndInvalidTaggedValuesRefuseBeforeClaim()throws Exception{
        Path source=fixture.seed("tampering");Path archive=export(source,"valid.archive",0);String valid=Files.readString(archive);
        var cases=new ArrayList<String>(List.of(valid+" {}",valid.substring(0,valid.length()-1),valid.replaceFirst("\"schema_version\":1","\"schema_version\":2"),
            valid.replaceFirst("\"schema_version\":1","\"schema_version\":1,\"schema_version\":1"),valid.replaceFirst("\"schema_version\":1","\"secret\":true,\"schema_version\":1")));
        var tree=(com.fasterxml.jackson.databind.node.ObjectNode)HecProtocol.JSON.readTree(valid);
        for(String key:List.of("sha256","byte_count","payload")){var bad=tree.deepCopy();bad.remove(key);cases.add(bad.toString());}
        var bad=tree.deepCopy();bad.put("sha256","0".repeat(64));cases.add(bad.toString());
        bad=tree.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)bad.at("/payload/state")).put("blocked",true);cases.add(bad.toString());
        bad=tree.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)bad.at("/payload/origin/completeness")).put("classification","complete-but-secret");cases.add(bad.toString());
        bad=tree.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)bad.at("/payload/state")).put("blocked",0);cases.add(bad.toString());
        bad=tree.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)bad.at("/payload/state")).put("unknown",1);cases.add(bad.toString());
        // Recompute integrity after a structural mutation: a valid checksum is not a validity bypass.
        for(Object envelope:List.of(Map.of("number",List.of("Double","NaN")),Map.of("map",List.of(List.of("duplicate","a"),List.of("duplicate","b"))),
                Map.of("map",List.of(List.of("@timestamp",Map.of("timestamp","not-an-instant")))))){
            bad=tree.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)bad.at("/payload/state/outbox/0")).set("envelope",HecProtocol.JSON.valueToTree(envelope));
            byte[] covered=HecProtocol.JSON.writeValueAsBytes(bad.get("payload"));bad.put("byte_count",covered.length);bad.put("sha256",TokenStore.fingerprint(covered));cases.add(bad.toString());
        }
        int i=0;for(String text:cases){Path input=root.resolve("bad-archive-"+i),target=root.resolve("bad-target-"+i++);Files.writeString(input,text);
            var result=cli("rebuild","--archive",input.toString(),"--assembly-directory",target.toString(),"--json");assertEquals(3,result.status(),text);assertEquals("",result.stdout());assertFalse(Files.exists(target));}
        for(int length:new int[]{0,1,64,valid.length()/2}){Files.writeString(root.resolve("partial"),valid.substring(0,length));assertEquals(3,cli("rebuild","--archive",root.resolve("partial").toString(),"--assembly-directory",root.resolve("partial-target").toString()).status());}
    }
    @Test void liveUnsafeOversizedAndOverlappingSourcesAndExistingDestinationsRefuse()throws Exception{
        Path source=fixture.seed("unsafe");
        try(var file=FileChannel.open(source.resolve("lock"),StandardOpenOption.WRITE);var lock=file.lock()){refusesExport(source,"locked.archive",4);}
        Files.createSymbolicLink(source.resolve("stray"),source.resolve("state"));refusesExport(source,"linked.archive",5);Files.delete(source.resolve("stray"));
        Path link=root.resolve("source-link");Files.createSymbolicLink(link,source);refusesExport(link,"source-link.archive",5);
        var overlap=cli("export","--assembly-directory",source.toString(),"--output",source.resolve("inside.archive").toString(),"--json");assertEquals(5,overlap.status());
        Path archive=export(source,"exclusive.archive",0);var before=Files.readAllBytes(archive);
        assertEquals(5,cli("export","--assembly-directory",source.toString(),"--output",archive.toString(),"--json").status());assertArrayEquals(before,Files.readAllBytes(archive));
        Path existing=root.resolve("existing");Files.createDirectory(existing);Files.writeString(existing.resolve("sentinel"),"retained");var inventory=fixture.inventory(existing);
        assertEquals(5,cli("rebuild","--archive",archive.toString(),"--assembly-directory",existing.toString(),"--json").status());assertEquals(inventory,fixture.inventory(existing));
        Path oversized=root.resolve("oversized");try(var file=FileChannel.open(oversized,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){file.position(S2SAssemblyRecovery.MAX_ARCHIVE);file.write(java.nio.ByteBuffer.wrap(new byte[]{1}));}
        assertEquals(5,cli("rebuild","--archive",oversized.toString(),"--assembly-directory",root.resolve("oversized-target").toString(),"--json").status());
    }
    @Test void concurrentClaimsHaveExactlyOneOwnerForArchiveAndDirectory()throws Exception{
        Path source=fixture.seed("claims");Path archive=export(source,"claim.archive",0);
        for(String command:List.of("export","rebuild")){
            Path destination=root.resolve("concurrent-"+command);String[] args=command.equals("export")?
                new String[]{command,"--assembly-directory",source.toString(),"--output",destination.toString(),"--json"}:
                new String[]{command,"--archive",archive.toString(),"--assembly-directory",destination.toString(),"--json"};
            Process first=fixture.child(S2SAssemblyRecovery.class.getName(),args),second=fixture.child(S2SAssemblyRecovery.class.getName(),args);
            try{assertTrue(first.waitFor(30,TimeUnit.SECONDS));assertTrue(second.waitFor(30,TimeUnit.SECONDS));assertEquals(Set.of(0,5),Set.of(first.exitValue(),second.exitValue()));}
            finally{S2SAssemblyInspectorTest.cleanup(first);S2SAssemblyInspectorTest.cleanup(second);}
        }
    }
    @Test void guardedStagingNeverReplacesAnExistingOrNewlyClaimedEmptyDirectory()throws Exception{
        Path source=fixture.seed("empty-destination-source"),input=export(source,"empty-destination.archive",0);
        for(boolean concurrent:List.of(false,true)){
            Path target=root.resolve("empty-destination-"+concurrent);var identity=new java.util.concurrent.atomic.AtomicReference<Object>();
            S2SSecureFiles.RunnableIO create=()->{Files.createDirectory(target,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));identity.set(Files.readAttributes(target,java.nio.file.attribute.BasicFileAttributes.class).fileKey());};
            if(!concurrent)create.run();
            var result=cli(point->{if(concurrent&&point.equals("destination.expose"))create.run();},"rebuild","--archive",input.toString(),"--assembly-directory",target.toString(),"--json");
            assertEquals(5,result.status());assertEquals("",result.stdout());assertEquals(identity.get(),Files.readAttributes(target,java.nio.file.attribute.BasicFileAttributes.class).fileKey());
            try(var entries=Files.list(target)){assertEquals(0,entries.count());}
        }
    }
    @Test void outputInodeAndAncestorReplacementCannotRedirectWritesOrDeleteAnotherOwnersEntry()throws Exception{
        Path source=fixture.seed("pin-source");var before=fixture.inventory(source);
        Path sentinel=root.resolve("private-sentinel");Files.writeString(sentinel,"unchanged");
        for(String kind:List.of("link","fifo")){
            Path output=root.resolve("race-"+kind),owned=root.resolve("owned-"+kind);
            var result=cli(point->{
                if(point.equals("archive.after-create")){
                    Files.move(output,owned);
                    if(kind.equals("link"))Files.createSymbolicLink(output,sentinel);
                    else try{Process fifo=new ProcessBuilder("mkfifo",output.toString()).start();try{assertTrue(fifo.waitFor(5,TimeUnit.SECONDS));assertEquals(0,fifo.exitValue());}finally{S2SAssemblyInspectorTest.cleanup(fifo);}}
                    catch(Exception error){throw new IOException(error);}
                }
            },"export","--assembly-directory",source.toString(),"--output",output.toString(),"--json");
            assertEquals(5,result.status());assertEquals("",result.stdout());assertTrue(Files.exists(output,LinkOption.NOFOLLOW_LINKS));assertEquals("unchanged",Files.readString(sentinel));
            assertEquals(before,fixture.inventory(source));
        }
        Path parent=root.resolve("output-parent"),moved=root.resolve("moved-output-parent");Files.createDirectory(parent,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        var result=cli(point->{if(point.equals("archive.after-create")){Files.move(parent,moved);Files.createSymbolicLink(parent,moved);}},
            "export","--assembly-directory",source.toString(),"--output",parent.resolve("archive").toString(),"--json");
        assertEquals(5,result.status());assertEquals("",result.stdout());assertEquals(before,fixture.inventory(source));
    }
    @Test void everyWriteFsyncPublicationAndCleanupFailureIsNonSuccessAndPreservesSources()throws Exception{
        Path source=fixture.seed("fault-source");Path archive=export(source,"fault.archive",0);var sourceBefore=fixture.inventory(source);byte[] inputBefore=Files.readAllBytes(archive);
        var points=new LinkedHashSet<String>();
        var baseline=cli(points::add,"rebuild","--archive",archive.toString(),"--assembly-directory",root.resolve("fault-baseline").toString(),"--json");assertEquals(0,baseline.status(),baseline.stderr());
        int i=0;for(String boundary:points){
            Path target=root.resolve("fault-"+i++);var result=cli(point->{if(point.equals(boundary))throw new IOException("private-fault");},"rebuild","--archive",archive.toString(),"--assembly-directory",target.toString(),"--json");
            assertEquals(5,result.status(),boundary+result.stderr());assertEquals("",result.stdout());assertFalse(result.stderr().contains("private-fault"));
            if(Files.exists(target.resolve("lock")))assertThrows(S2SAssemblyInspector.Refusal.class,()->S2SAssemblyInspector.inspect(target),boundary);
            assertEquals(sourceBefore,fixture.inventory(source));assertArrayEquals(inputBefore,Files.readAllBytes(archive));
        }
        for(String boundary:List.of("archive.create","archive.write","archive.sync","archive.directory-sync","archive.cleanup")){
            Path output=root.resolve(boundary);var result=cli(point->{if(point.equals(boundary)||boundary.equals("archive.cleanup")&&point.equals("archive.write"))throw new IOException("private-fault");},"export","--assembly-directory",source.toString(),"--output",output.toString(),"--json");
            assertEquals(5,result.status(),boundary);assertEquals("",result.stdout());assertEquals(sourceBefore,fixture.inventory(source));
            if(Files.exists(output))assertThrows(IOException.class,()->S2SAssemblyRecovery.readArchive(Files.readAllBytes(output)));
        }
    }
    @Test void processHaltLeavesPartialArchivesInvalidAndRebuildsExplicitlyUnadoptable()throws Exception{
        Path source=fixture.seed("crash-source");Path archive=export(source,"crash.archive",0);var before=fixture.inventory(source);
        for(String point:List.of("archive.write","destination.create","destination.mkdir","destination.recovery-incomplete.create","destination.recovery-incomplete.write",
                "destination.expose","destination.exposed","destination.lock.create","destination.state.write","destination.snapshot-v3-1.write","destination.current-v3.directory-sync","destination.finish","destination.finish-sync")){
            Path target=root.resolve("crash-"+point.replace('.','-'));boolean export=point.startsWith("archive");
            Process child=fixture.child(getClass().getName(),point,export?"export":"rebuild",export?source.toString():archive.toString(),target.toString());
            try{assertTrue(child.waitFor(30,TimeUnit.SECONDS));assertEquals(73,child.exitValue(),point);}finally{S2SAssemblyInspectorTest.cleanup(child);}
            if(export)assertThrows(IOException.class,()->S2SAssemblyRecovery.readArchive(Files.readAllBytes(target)));
            else if(point.equals("destination.finish-sync"))same(recoveredCopy(source,"crash-reference"),recoveredCopy(target,"crash-complete"));
            else if(Files.exists(target)){
                assertThrows(S2SAssemblyInspector.Refusal.class,()->S2SAssemblyInspector.inspect(target));
                try(var store=new S2SAssemblyStore(target,1L<<20)){assertThrows(IOException.class,store::recover);}
            }else assertFalse(Files.exists(target,LinkOption.NOFOLLOW_LINKS));
            assertEquals(before,fixture.inventory(source));fixture.released(source);
        }
    }
    @Test void failedFinalSyncAndFailedGuardRestorationNeverReportSuccessButCanLeaveCompleteOutput()throws Exception{
        Path source=fixture.seed("double-fault-source"),input=export(source,"double-fault.archive",0),target=root.resolve("double-fault-target");
        var before=fixture.inventory(source);
        var result=cli(point->{if(point.equals("destination.finish-sync")||point.equals("destination.invalidate.create"))throw new IOException("private-double-fault");},
            "rebuild","--archive",input.toString(),"--assembly-directory",target.toString(),"--json");
        assertEquals(5,result.status());assertEquals("",result.stdout());assertFalse(result.stderr().contains("private"));
        assertFalse(Files.exists(target.resolve("recovery-incomplete")));assertEquals(0,S2SAssemblyInspector.inspect(target).status());
        same(recoveredCopy(source,"double-reference"),recoveredCopy(target,"double-copy"));assertEquals(before,fixture.inventory(source));
    }
    @Test void launcherTermAndIntReapTheJavaLockHolderAndReturnValueFreeExitSeventy()throws Exception{
        Path source=fixture.seed("launcher-source");var before=fixture.inventory(source);
        for(String signal:List.of("TERM","INT")){
            Path home=root.resolve("runtime-"+signal),plugin=home.resolve("plugin");
            Files.createDirectories(home.resolve("jdk/bin"));Files.createDirectories(home.resolve("logstash-core/lib/jars"));
            Files.createDirectories(plugin.resolve("lib"));Files.createDirectories(plugin.resolve("vendor/jars"));
            Files.copy(Path.of("lib/splunk-hec-recover"),plugin.resolve("lib/splunk-hec-recover"));Files.writeString(plugin.resolve("VERSION"),"0.6.0\n");
            Files.write(plugin.resolve("vendor/jars/logstash-input-splunk_hec-0.6.0.jar"),new byte[0]);
            Path fake=home.resolve("jdk/bin/java");Files.writeString(fake,"#!/bin/sh\nexec \"$TEST_JAVA\" -cp \"$TEST_CP\" org.logstashplugins.hec.S2SAssemblyRecoveryTest hold \"$TEST_SOURCE\"\n");
            Files.setPosixFilePermissions(fake,PosixFilePermissions.fromString("rwx------"));
            var builder=new ProcessBuilder("/bin/sh",plugin.resolve("lib/splunk-hec-recover").toString(),"--json");
            builder.environment().putAll(Map.of("LOGSTASH_HOME",home.toString(),"TEST_JAVA",Path.of(System.getProperty("java.home"),"bin/java").toString(),"TEST_CP",fixture.classpath(),"TEST_SOURCE",source.toString()));
            Process launcher=builder.start();ProcessHandle holder=null;
            try{
                var ready=CompletableFuture.supplyAsync(()->{try{return launcher.inputReader().readLine();}catch(IOException error){throw new UncheckedIOException(error);}}).get(10,TimeUnit.SECONDS);
                assertNotNull(ready);assertTrue(ready.startsWith("ready "));holder=ProcessHandle.of(Long.parseLong(ready.substring(6))).orElseThrow();
                Process kill=new ProcessBuilder("/bin/sh","-c","kill -\"$1\" \"$2\"","recovery-signal",signal,Long.toString(launcher.pid())).start();
                try{assertTrue(kill.waitFor(5,TimeUnit.SECONDS));assertEquals(0,kill.exitValue());}finally{S2SAssemblyInspectorTest.cleanup(kill);}
                assertTrue(launcher.waitFor(12,TimeUnit.SECONDS));assertEquals(70,launcher.exitValue());assertFalse(holder.isAlive());
                assertEquals("",new String(launcher.getInputStream().readAllBytes()));
                String diagnostics=new String(launcher.getErrorStream().readAllBytes());var error=HecProtocol.JSON.readTree(diagnostics);
                assertEquals("interrupted",error.at("/error/code").asText());assertFalse(diagnostics.contains(source.toString()));assertFalse(diagnostics.contains("private"));
                fixture.released(source);assertEquals(before,fixture.inventory(source));
            }finally{S2SAssemblyInspectorTest.cleanup(launcher);if(holder!=null&&holder.isAlive()){holder.destroyForcibly();holder.onExit().get(5,TimeUnit.SECONDS);}}
        }
    }
    public static void main(String[] args)throws Exception{
        if(args[0].equals("hold")){
            try(var file=FileChannel.open(Path.of(args[1]).resolve("lock"),StandardOpenOption.READ);var lock=file.lock(0,Long.MAX_VALUE,true)){
                System.out.println("ready "+ProcessHandle.current().pid());System.out.flush();Thread.sleep(60000);
            }return;
        }
        var faults=(S2SAssemblyInspector.Faults)point->{if(point.equals(args[0]))Runtime.getRuntime().halt(73);};
        if(args[1].equals("export"))cliMain(faults,"export","--assembly-directory",args[2],"--output",args[3],"--json");
        else cliMain(faults,"rebuild","--archive",args[2],"--assembly-directory",args[3],"--json");
    }
    static void cliMain(S2SAssemblyInspector.Faults faults,String... args){System.exit(S2SAssemblyRecovery.run(args,System.out,System.err,faults));}
    @Test void strictCliAndValueFreeSchemas(){
        assertEquals(0,cli("--help","--json").status());
        for(String[] args:List.of(new String[]{},new String[]{"export","--archive","private-path"},new String[]{"rebuild","--output","private-path"},
            new String[]{"export","--json","--json"},new String[]{"export","--unknown-private","--json"},new String[]{"--json","export"},new String[]{"export","--assembly-directory","--json"})){
            var result=cli(args);assertEquals(64,result.status());assertEquals("",result.stdout());assertFalse(result.stderr().contains("private"));
        }
    }
}
