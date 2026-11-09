package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.LINUX)
class S2SAssemblyInspectorTest {
    @TempDir Path temporary;
    Path root;
    S2SJournalTest fixture;
    @BeforeEach void setup()throws Exception{
        root=temporary.toRealPath();fixture=new S2SJournalTest();fixture.directory=root;
    }
    Path seed(String name)throws Exception{
        Path path=root.resolve(name);
        try(var assembly=fixture.assembler(path,1L<<20,p->{})){fixture.accept(assembly,0,"START private-payload\nSTART private-tail");}
        return path;
    }
    record Entry(String hash,Object key,long size,FileTime mtime,Set<PosixFilePermission> mode) {}
    Map<String,Entry> inventory(Path path)throws Exception{
        var result=new TreeMap<String,Entry>();
        if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS))return result;
        try(var files=Files.walk(path)){
            for(Path file:files.toList()){
                var attrs=Files.readAttributes(file,PosixFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
                String hash=attrs.isRegularFile()?TokenStore.fingerprint(Files.readAllBytes(file)):attrs.isSymbolicLink()?Files.readSymbolicLink(file).toString():"directory/special";
                result.put(path.relativize(file).toString(),new Entry(hash,attrs.fileKey(),attrs.size(),attrs.lastModifiedTime(),attrs.permissions()));
            }
        }
        return result;
    }
    S2SAssemblyInspector.Result inspect(Path path,int status)throws Exception{
        var before=inventory(path);
        try{var result=S2SAssemblyInspector.inspect(path);assertEquals(status,result.status());return result;}
        finally{assertEquals(before,inventory(path),"inspection must preserve bytes, entries, identity, modes and mtimes");}
    }
    void refuses(Path path,int status,String code)throws Exception{
        var before=inventory(path);
        try{var error=assertThrows(S2SAssemblyInspector.Refusal.class,()->S2SAssemblyInspector.inspect(path));assertEquals(status,error.status);assertEquals(code,error.code);}
        finally{assertEquals(before,inventory(path));}
    }
    void released(Path path)throws Exception{
        try(var channel=FileChannel.open(path.resolve("lock"),StandardOpenOption.WRITE);var lock=channel.tryLock()){assertNotNull(lock);}
    }
    @Test void publishedSummaryMatchesProductionCopyAndDoesNotDiscloseValues()throws Exception{
        Path path=seed("published");var result=inspect(path,0);var summary=result.summary();
        Path copy=root.resolve("recovery-copy");S2SJournalTest.copy(path,copy);var state=fixture.recovered(copy,1L<<20);
        assertEquals(state.pending().size(),summary.get("pending"));assertEquals(state.outbox().size(),summary.get("outbox"));
        assertEquals(state.receipts().size(),summary.get("receipts"));assertEquals(state.blocked(),summary.get("blocked"));
        assertEquals(1L,summary.get("sequence"));assertEquals(1L,summary.get("transactions"));assertEquals("published_v3",summary.get("authority"));
        assertEquals(0L,summary.get("publication_candidates"),"the active snapshot and journal are not unpublished candidates");
        assertEquals("not_evaluated",summary.get("restart_compatibility"));assertFalse(HecProtocol.JSON.writeValueAsString(summary).contains("private-"));released(path);
    }
    @Test void legacyOriginalIsReadWithoutMigrationAndPolicyIsNotEvaluated()throws Exception{
        Path source=seed("source");var state=fixture.recovered(source,1L<<20);Path path=root.resolve("legacy");Files.createDirectory(path);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));
        Files.write(path.resolve("lock"),new byte[0]);Files.write(path.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(state)));
        var summary=inspect(path,0).summary();assertEquals("original_v2",summary.get("authority"));assertEquals(1,summary.get("pending"));assertEquals(1,summary.get("outbox"));
        assertEquals(Set.of("lock","state"),inventory(path).keySet().stream().filter(s->!s.isEmpty()).collect(java.util.stream.Collectors.toSet()));released(path);
    }
    @Test void everyShortHeaderAndAuthenticatedShortPayloadReportsPrefixWithoutTruncation()throws Exception{
        Path original=seed("suffix-seed");byte[] prefix=Files.readAllBytes(S2SAssemblyTest.journal(original));
        try(var assembly=fixture.assembler(original,1L<<20,p->{})){fixture.accept(assembly,37,"tail");}
        byte[] all=Files.readAllBytes(S2SAssemblyTest.journal(original));
        for(int length=1;length<88;length++)checkSuffix(original,prefix,all,length);
        for(int length:new int[]{88,89,all.length-prefix.length-1})checkSuffix(original,prefix,all,length);
    }
    void checkSuffix(Path original,byte[] prefix,byte[] all,int length)throws Exception{
        Path path=root.resolve("suffix-"+length);S2SJournalTest.copy(original,path);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));
        Files.write(S2SAssemblyTest.journal(path),Arrays.copyOf(all,prefix.length+length));
        var summary=inspect(path,2).summary();assertEquals(1L,summary.get("sequence"));assertEquals(Map.of("offset",(long)prefix.length,"length",(long)length),summary.get("incomplete_suffix"));released(path);
    }
    @Test void completeFramingChecksumSequenceOperationAndCodecCorruptionNeverFallback()throws Exception{
        Path source=seed("corrupt-seed");byte[] journal=Files.readAllBytes(S2SAssemblyTest.journal(source));
        for(int offset:new int[]{0,4,8,16,24,56,journal.length-1}){
            Path path=root.resolve("corrupt-"+offset);S2SJournalTest.copy(source,path);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));
            byte[] bytes=journal.clone();bytes[offset]^=1;Files.write(S2SAssemblyTest.journal(path),bytes);refuses(path,3,"corrupt_state");released(path);
        }
        var recovered=fixture.recovered(source,1L<<20);
        var tx=new S2SAssemblyStore.Transaction(recovered.configuration(),List.of("missing"),List.of(),List.of(),List.of(),List.of(),Map.of(),null,null,false);
        append(source,2,HecProtocol.JSON.writeValueAsBytes(tx));refuses(source,3,"corrupt_state");released(source);
        Path nativePath=seed("native-corrupt");
        var invalid=new S2SAssemblyStore.Transaction(recovered.configuration(),List.of(),List.of(),List.of(),List.of(new S2SStreamAssembler.Output("new",Map.of("map",List.of(List.of("secret",Map.of("number",List.of("Double","NaN"))))),null)),List.of(),Map.of(),null,null,false);
        append(nativePath,2,HecProtocol.JSON.writeValueAsBytes(invalid));refuses(nativePath,3,"corrupt_state");released(nativePath);
    }
    static void append(Path path,long sequence,byte[] payload)throws Exception{
        var header=ByteBuffer.allocate(88).putInt(0x53325333).putInt(3).putLong(sequence).putLong(payload.length);
        header.put(S2SAssemblyReader.digest(Arrays.copyOf(header.array(),24))).put(S2SAssemblyReader.digest(payload));
        Files.write(S2SAssemblyTest.journal(path),header.array(),StandardOpenOption.APPEND);Files.write(S2SAssemblyTest.journal(path),payload,StandardOpenOption.APPEND);
    }
    @Test void unpublishedCandidatesAndBackupAreNeverPromoted()throws Exception{
        Path path=seed("unpublished");Files.delete(path.resolve("current-v3"));
        var summary=inspect(path,2).summary();assertEquals("none",summary.get("authority"));assertEquals("ambiguous",summary.get("classification"));assertFalse(summary.containsKey("pending"));released(path);
        Files.delete(path.resolve("established-v3"));Files.write(path.resolve("backup-v2"),new byte[]{1,2,3});
        summary=inspect(path,2).summary();assertEquals("present_not_current",summary.get("backup"));assertFalse(summary.containsKey("pending"));released(path);
    }
    @Test void corruptPublishedPointerNeverUsesValidBackup()throws Exception{
        Path path=seed("pointer");Files.write(path.resolve("backup-v2"),Files.readAllBytes(path.resolve("snapshot-v3-1")));
        byte[] pointer=Files.readAllBytes(path.resolve("current-v3"));pointer[pointer.length-1]^=1;Files.write(path.resolve("current-v3"),pointer);
        refuses(path,3,"corrupt_state");released(path);
    }
    @Test void missingDirectoriesLocksLinksSpecialFilesAndPublicDirectoriesRefuse()throws Exception{
        refuses(root.resolve("missing"),5,"unsafe_storage");
        Path path=seed("unsafe");Files.delete(path.resolve("lock"));refuses(path,5,"unsafe_storage");
        Files.createSymbolicLink(path.resolve("lock"),path.resolve("state"));refuses(path,5,"unsafe_storage");Files.delete(path.resolve("lock"));Files.write(path.resolve("lock"),new byte[0]);
        Files.createSymbolicLink(path.resolve("stray"),path.resolve("state"));refuses(path,5,"unsafe_storage");Files.delete(path.resolve("stray"));
        Path link=root.resolve("linked");Files.createSymbolicLink(link,path);refuses(link,5,"unsafe_storage");
        Files.createDirectory(path.resolve("special"));refuses(path,5,"unsafe_storage");Files.delete(path.resolve("special"));
        Process fifo=new ProcessBuilder("mkfifo",path.resolve("fifo").toString()).start();assertTrue(fifo.waitFor(5,TimeUnit.SECONDS));assertEquals(0,fifo.exitValue());refuses(path,5,"unsafe_storage");Files.delete(path.resolve("fifo"));
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwxr-xr-x"));refuses(path,5,"unsafe_storage");
    }
    @Test void physicalEntryJsonDepthAndStateBudgetsFailClosed()throws Exception{
        Path entries=seed("entries");for(int i=0;i<257;i++)Files.write(entries.resolve("entry-"+i),new byte[0]);refuses(entries,5,"budget_exceeded");released(entries);
        Path large=seed("large");try(var channel=FileChannel.open(large.resolve("huge"),StandardOpenOption.CREATE,StandardOpenOption.WRITE)){channel.position(S2SAssemblyReader.HISTORY+65);channel.write(ByteBuffer.wrap(new byte[]{1}));}
        // Sparse oversized input: inventory metadata without hashing the intentionally huge file in this test.
        long size=Files.size(large.resolve("huge"));var error=assertThrows(S2SAssemblyInspector.Refusal.class,()->S2SAssemblyInspector.inspect(large));assertEquals("budget_exceeded",error.code);assertEquals(size,Files.size(large.resolve("huge")));released(large);
        Path depth=seed("depth");Files.write(depth.resolve("current-v3"),S2SJournalTest.wrap(("[".repeat(65)+"0"+"]".repeat(65)).getBytes()));refuses(depth,5,"budget_exceeded");released(depth);
        var state=new S2SStreamAssembler.State("configuration",Map.of(),Collections.nCopies(40001,new S2SStreamAssembler.Output("id",S2SAssemblyStore.encode(Map.of()),null)),Map.of(),false);
        Path bound=root.resolve("state-bound");Files.createDirectory(bound);Files.setPosixFilePermissions(bound,PosixFilePermissions.fromString("rwx------"));Files.write(bound.resolve("lock"),new byte[0]);Files.write(bound.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(state)));refuses(bound,5,"budget_exceeded");released(bound);
    }
    record Cli(int status,String stdout,String stderr) {}
    @Test void replayRecordAndTaggedNumericBudgetsAreExplicit()throws Exception{
        Path path=seed("record-bound");
        var pointer=S2SAssemblyReader.pointer(S2SAssemblyReader.checked(Files.readAllBytes(path.resolve("current-v3"))),S2SStreamAssembler.recoveryMapper(4096));
        var snapshot=S2SAssemblyReader.snapshot(S2SAssemblyReader.checked(Files.readAllBytes(path.resolve("snapshot-v3-"+pointer.generation()))),pointer,S2SStreamAssembler.recoveryMapper(1L<<20));
        try(var journal=FileChannel.open(S2SAssemblyTest.journal(path),StandardOpenOption.READ)){
            assertThrows(S2SAssemblyReader.BudgetException.class,()->S2SAssemblyReader.replay(journal,snapshot.state(),snapshot.sequence(),S2SStreamAssembler.recoveryMapper(1L<<20),new S2SAssemblyReader.Validation(),0));
        }
        var state=new S2SStreamAssembler.State("configuration",Map.of(),List.of(new S2SStreamAssembler.Output("id",Map.of("map",List.of(List.of("native",Map.of("number",List.of("BigInteger","1".repeat(1025)))))),null)),Map.of(),false);
        Path legacy=root.resolve("numeric-bound");Files.createDirectory(legacy);Files.setPosixFilePermissions(legacy,PosixFilePermissions.fromString("rwx------"));
        Files.write(legacy.resolve("lock"),new byte[0]);Files.write(legacy.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(state)));
        refuses(legacy,5,"budget_exceeded");released(legacy);
    }
    Cli cli(String input,String... args)throws Exception{
        return cli(S2SAssemblyInspector.NO_FAULTS,input,args);
    }
    Cli cli(S2SAssemblyInspector.Faults faults,String input,String... args)throws Exception{
        var out=new ByteArrayOutputStream();var err=new ByteArrayOutputStream();
        int status=S2SAssemblyInspector.run(args,new ByteArrayInputStream(input.getBytes()),new PrintStream(out),new PrintStream(err),faults);return new Cli(status,out.toString(),err.toString());
    }
    @Test void cliSchemasInputPrecedenceStrictUsageAndValueFreeErrors()throws Exception{
        assertEquals(0,cli("","--help").status);var help=cli("","--help","--json");assertEquals(1,HecProtocol.JSON.readTree(help.stdout).get("schema_version").asInt());
        Path path=seed("cli");var before=inventory(path);
        var result=cli("{\"assembly_directory\":\"/does-not-exist\",\"json\":true}","--stdin","--assembly-directory",path.toString());assertEquals(0,result.status);assertEquals("v3",HecProtocol.JSON.readTree(result.stdout).get("format").asText());
        assertEquals(0,cli("{\"schema_version\":1,\"json\":true}","--stdin","--assembly-directory",path.toString(),"--json").status);
        for(String input:List.of("{\"unknown-secret\":true}","{\"json\":true,\"json\":false}","[]","{\"schema_version\":2}","{\"assembly_directory\":null}","{} {}")){
            var failure=cli(input,"--stdin","--assembly-directory",path.toString(),"--json");assertEquals(64,failure.status,input);assertEquals("",failure.stdout);assertFalse(failure.stderr.contains("secret"));
        }
        assertEquals(64,cli("","--json").status);assertEquals(64,cli("","--stdin","--input-file","no-file","--json").status);
        assertEquals(64,cli("","--assembly-directory","--json").status);assertEquals(64,cli("","--input-file","--json").status);
        Path input=root.resolve("input.json");Files.writeString(input,HecProtocol.JSON.writeValueAsString(Map.of("assembly_directory",path.toString(),"json",true)));
        assertEquals(0,cli("","--input-file",input.toString()).status);
        assertEquals(64,cli("","--unknown-private","--json").status);assertEquals(before,inventory(path));released(path);
    }
    String classpath(){return System.getProperty("java.class.path")+File.pathSeparator+String.join(File.pathSeparator,List.of(
        S2SAssemblyInspectorTest.class.getProtectionDomain().getCodeSource().getLocation().getPath(),S2SAssemblyInspector.class.getProtectionDomain().getCodeSource().getLocation().getPath(),"vendor/jars/*",".cache/logstash-jars/*"));}
    Process child(String main,String... args)throws Exception{
        var command=new ArrayList<>(List.of(Path.of(System.getProperty("java.home"),"bin/java").toString(),"--add-opens=java.base/sun.nio.fs=ALL-UNNAMED","-cp",classpath(),main));command.addAll(List.of(args));return new ProcessBuilder(command).start();
    }
    static void cleanup(Process process)throws Exception{
        try{
            if(process.isAlive())process.destroy();
            if(!process.waitFor(2,TimeUnit.SECONDS)){process.destroyForcibly();assertTrue(process.waitFor(5,TimeUnit.SECONDS),"child cleanup deadline");}
        }finally{process.getInputStream().close();process.getErrorStream().close();process.getOutputStream().close();}
    }
    @Test void subprocessCliAndJavaSharedExclusiveLocksAreCompatible()throws Exception{
        Path path=seed("locks");var before=inventory(path);
        for(String mode:List.of("exclusive","shared")){
            Process holder=child(getClass().getName(),path.toString(),mode);
            try{
                var ready=holder.inputReader().readLine();assertEquals("ready",ready);
                if(mode.equals("exclusive"))refuses(path,4,"locked");else inspect(path,0);
                Process cli=child(S2SAssemblyInspector.class.getName(),"--assembly-directory",path.toString(),"--json");
                try{
                    assertTrue(cli.waitFor(20,TimeUnit.SECONDS));assertEquals(mode.equals("exclusive")?4:0,cli.exitValue());
                    if(mode.equals("exclusive")){assertEquals(0,cli.getInputStream().readAllBytes().length);assertTrue(new String(cli.getErrorStream().readAllBytes()).contains("locked"));}
                }finally{cleanup(cli);}
            }finally{cleanup(holder);}
        }
        assertEquals(before,inventory(path));released(path);
    }
    public static void main(String[] args)throws Exception{
        if(args[0].equals("sleep")){Thread.sleep(60000);return;}
        boolean shared=args[1].equals("shared");
        try(var channel=FileChannel.open(Path.of(args[0]).resolve("lock"),shared?StandardOpenOption.READ:StandardOpenOption.WRITE);var lock=channel.lock(0,Long.MAX_VALUE,shared)){
            System.out.println("ready");System.out.flush();Thread.sleep(30000);
        }
    }
    @Test void timedOutCliChildIsTerminatedAndAwaited()throws Exception{
        Process child=child(getClass().getName(),"sleep");
        try{assertFalse(child.waitFor(100,TimeUnit.MILLISECONDS));}finally{cleanup(child);}
        assertFalse(child.isAlive());
    }
    @Test void checkedMalformedStatesRejectWithoutPolicyOrPayloadDisclosure()throws Exception{
        Path source=seed("malformed-source");var recovered=fixture.recovered(source,1L<<20);
        var original=HecProtocol.JSON.valueToTree(recovered);String key=recovered.pending().keySet().iterator().next();
        var controls=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();
        for(String field:List.of("text","delimiter","origin","attributes","contributions","envelope")){
            var state=original.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)state.get("pending").get(key)).putNull(field);controls.add(state);
        }
        for(String field:List.of("offset","sequence","logical_offset","line","sha256")){
            var state=original.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)state.get("pending").get(key).get("contributions").get(0)).remove(field);controls.add(state);
        }
        for(Object template:List.of(S2SAssemblyReader.encode(Map.of("host",3L)),S2SAssemblyReader.encode(Map.of("fields",List.of())),
                S2SAssemblyReader.encode(Map.of("@metadata","invalid")),S2SAssemblyReader.encode(Map.of("@timestamp","invalid")))){
            var state=original.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)state.get("pending").get(key)).set("envelope",HecProtocol.JSON.valueToTree(template));controls.add(state);
        }
        int index=0;
        for(var state:controls){
            Path path=root.resolve("malformed-"+index++);Files.createDirectory(path);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));Files.write(path.resolve("lock"),new byte[0]);
            Files.write(path.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(state)));refuses(path,3,"corrupt_state");released(path);
            var before=inventory(path);var result=cli("","--assembly-directory",path.toString(),"--json");assertEquals(3,result.status);assertEquals("",result.stdout);assertFalse(result.stderr.contains("private-"));assertEquals(before,inventory(path));
            Path copy=root.resolve("writer-"+index);S2SJournalTest.copy(path,copy);assertThrows(IOException.class,()->fixture.assembler(copy,1L<<20,p->{}));
        }
    }
    @Test void inputFilePinsAncestorsAndRefusesReplacementBeforeDataOpen()throws Exception{
        Path spool=seed("input-spool");var before=inventory(spool);Path parent=root.resolve("input-parent");Files.createDirectory(parent);
        Path input=parent.resolve("input.json");Files.writeString(input,"{\"schema_version\":1}");
        String[] args={"--input-file",input.toString(),"--assembly-directory",spool.toString(),"--json"};
        assertEquals(0,cli("",args).status);
        var opened=new java.util.concurrent.atomic.AtomicBoolean();
        var result=cli(point->{
            if(point.equals("input.after-pin")){Files.move(parent,root.resolve("moved-parent"));Files.createSymbolicLink(parent,root.resolve("moved-parent"));}
            if(point.equals("input.open-data"))opened.set(true);
        },"",args);
        assertEquals(5,result.status);assertFalse(opened.get());assertEquals(before,inventory(spool));
        Files.delete(parent);Files.move(root.resolve("moved-parent"),parent);
        result=cli(point->{
            if(point.equals("input.before-pin")){
                Files.move(input,parent.resolve("original.json"));
                try{Process process=new ProcessBuilder("mkfifo",input.toString()).start();try{assertTrue(process.waitFor(5,TimeUnit.SECONDS));assertEquals(0,process.exitValue());}finally{cleanup(process);}}
                catch(Exception error){throw new IOException(error);}
            }
            if(point.equals("input.open-data"))opened.set(true);
        },"",args);
        assertEquals(5,result.status);assertFalse(opened.get());assertEquals(before,inventory(spool));
        Files.delete(input);Files.createSymbolicLink(input,parent.resolve("original.json"));assertEquals(5,cli("",args).status);
    }
    @Test void storageFaultsAreValueFreeExitFiveAndCheckedCorruptionIsThree()throws Exception{
        Path spool=seed("io-faults");var before=inventory(spool);
        for(String boundary:List.of("storage.open","storage.enumerate","storage.read","storage.journal-read")){
            var result=cli(point->{if(point.equals(boundary))throw new IOException("unexpected-private-path");},"","--assembly-directory",spool.toString(),"--json");
            assertEquals(5,result.status,boundary);assertEquals("",result.stdout);assertEquals("unsafe_storage",HecProtocol.JSON.readTree(result.stderr).get("error").get("code").asText());assertFalse(result.stderr.contains("private-path"));released(spool);
        }
        var result=cli(point->{if(point.equals("storage.enumerate"))throw new DirectoryIteratorException(new IOException("private-path"));},"","--assembly-directory",spool.toString(),"--json");assertEquals(5,result.status);assertFalse(result.stderr.contains("private-path"));
        assertEquals(before,inventory(spool));
        var file=FileChannel.open(spool.resolve("state"),StandardOpenOption.READ);file.close();assertThrows(S2SAssemblyReader.ReadFailure.class,()->S2SAssemblyReader.read(file,0,new byte[1]));
        Files.writeString(spool.resolve("current-v3"),"checked-corrupt");refuses(spool,3,"corrupt_state");
    }
    @Test void pinnedFileGrowthDoesNotChangeTheAdmittedAllocation()throws Exception{
        Path spool=seed("growth");Path pointer=spool.resolve("current-v3");byte[] original=Files.readAllBytes(pointer);
        var expanded=new java.util.concurrent.atomic.AtomicBoolean();
        var result=cli(point->{
            if(point.equals("storage.read")&&expanded.compareAndSet(false,true))
                try(var channel=FileChannel.open(pointer,StandardOpenOption.WRITE)){
                    channel.position(Integer.MAX_VALUE);channel.write(ByteBuffer.wrap(new byte[]{1}));
                }
        },"","--assembly-directory",spool.toString(),"--json");
        assertEquals(5,result.status);assertTrue(result.stdout.isEmpty());
        Files.write(pointer,original);released(spool);
    }
    @Test void capturesPublishedSchemasAndActualOutputFamilies()throws Exception{
        Path spool=seed("schema-spool");var cases=new ArrayList<Map<String,Object>>();
        java.util.function.Consumer<Cli> capture=result->{try{cases.add(Map.of("status",result.status,"stdout",result.stdout.isBlank()?"":HecProtocol.JSON.readTree(result.stdout),"stderr",result.stderr.isBlank()?"":HecProtocol.JSON.readTree(result.stderr)));}catch(IOException error){throw new UncheckedIOException(error);}};
        var help=HecProtocol.JSON.readTree(cli("","--help","--json").stdout);
        capture.accept(cli("","--assembly-directory",spool.toString(),"--json"));
        Files.write(S2SAssemblyTest.journal(spool),new byte[]{1},StandardOpenOption.APPEND);capture.accept(cli("","--assembly-directory",spool.toString(),"--json"));
        Files.delete(spool.resolve("current-v3"));capture.accept(cli("","--assembly-directory",spool.toString(),"--json"));
        capture.accept(cli("","--json"));
        var recovered=fixture.recovered(seed("schema-legacy-source"),1L<<20);Path legacy=root.resolve("schema-legacy");Files.createDirectory(legacy);Files.setPosixFilePermissions(legacy,PosixFilePermissions.fromString("rwx------"));Files.write(legacy.resolve("lock"),new byte[0]);Files.write(legacy.resolve("state"),S2SJournalTest.wrap(HecProtocol.JSON.writeValueAsBytes(recovered)));
        capture.accept(cli("","--assembly-directory",legacy.toString(),"--json"));
        Path output=Path.of(System.getProperty("inspection.captureFile","build/inspection-captures/manual/captured.json"));Files.createDirectories(output.getParent());
        Files.write(output,HecProtocol.JSON.writeValueAsBytes(Map.of("run_id",System.getProperty("inspection.runId","manual"),"help",help,"cases",cases)));
    }
    @Test void compactedNonemptySnapshotAndTornPrefixMatchProductionCopy()throws Exception{
        Path path=seed("compacted");
        try(var store=new S2SAssemblyStore(path,1L<<20)){
            var state=S2SStreamAssembler.recoveryMapper(1L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);store.initialize(state);store.compact();
        }
        long offset=fixture.recovered(path,1L<<20).pending().values().iterator().next().offset();
        try(var assembly=fixture.assembler(path,1L<<20,p->{})){fixture.accept(assembly,offset,"continued");}
        for(boolean torn:List.of(false,true)){
            if(torn)Files.write(S2SAssemblyTest.journal(path),new byte[]{1,2,3},StandardOpenOption.APPEND);
            var result=inspect(path,torn?2:0).summary();assertEquals(2L,result.get("generation"));assertEquals(1L,result.get("snapshot_sequence"));assertEquals(2L,result.get("sequence"));assertEquals(1L,result.get("transactions"));
            Path copy=root.resolve("compacted-copy-"+torn);S2SJournalTest.copy(path,copy);
            try(var store=new S2SAssemblyStore(copy,1L<<20)){
                var state=S2SStreamAssembler.recoveryMapper(1L<<20).readValue(store.recover(),S2SStreamAssembler.State.class);
                assertEquals(state.pending().size(),result.get("pending"));assertEquals(state.outbox().size(),result.get("outbox"));assertEquals(state.receipts().size(),result.get("receipts"));assertEquals(state.blocked(),result.get("blocked"));
                assertEquals(state.pending().values().stream().mapToLong(p->p.contributions().size()).sum(),result.get("contributions"));
                assertEquals(HttpTlsTest.privateField(store,"generation"),result.get("generation"));assertEquals(HttpTlsTest.privateField(store,"sequence"),result.get("sequence"));
            }
            released(path);
        }
    }
    @Test void launcherBootstrapFailuresAreStructuredAndValueFree()throws Exception{
        Path home=root.resolve("runtime"),plugin=home.resolve("vendor/local_gems/fixture/plugin");Files.createDirectories(plugin.resolve("lib"));Files.createDirectories(plugin.resolve("vendor/jars"));
        Files.copy(Path.of("lib/splunk-hec-inspect"),plugin.resolve("lib/splunk-hec-inspect"));Files.writeString(plugin.resolve("VERSION"),"0.4.0\n");
        Files.createSymbolicLink(home.resolve("jdk"),Path.of(System.getProperty("java.home")));Files.createDirectories(home.resolve("logstash-core/lib"));
        Files.createSymbolicLink(home.resolve("logstash-core/lib/jars"),Path.of(".cache/logstash-jars").toAbsolutePath());
        // Installed Logstash supplies Joda via its JRuby bundle. Supply the same
        // required class in this synthetic runtime without changing the real cache.
        Files.createDirectories(home.resolve("vendor/jruby/lib"));
        Files.createSymbolicLink(home.resolve("vendor/jruby/lib/jruby.jar"),Path.of(org.joda.time.ReadableInstant.class.getProtectionDomain().getCodeSource().getLocation().toURI()));
        Path jar=plugin.resolve("vendor/jars/logstash-input-splunk_hec-0.4.0.jar");
        var names=new HashSet<String>();
        try(var output=new java.util.jar.JarOutputStream(Files.newOutputStream(jar))){
            Path classes=Path.of(S2SAssemblyInspector.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            try(var files=Files.walk(classes)){
                for(Path file:files.filter(Files::isRegularFile).toList()){
                    String name=classes.relativize(file).toString();names.add(name);output.putNextEntry(new java.util.jar.JarEntry(name));Files.copy(file,output);output.closeEntry();
                }
            }
            try(var dependencies=new java.util.jar.JarFile("vendor/jars/logstash-input-splunk_hec-0.4.0.jar")){
                for(var entry:Collections.list(dependencies.entries()))if(!entry.isDirectory()&&!entry.getName().startsWith("org/logstashplugins/")&&names.add(entry.getName())){
                    output.putNextEntry(new java.util.jar.JarEntry(entry.getName()));try(var input=dependencies.getInputStream(entry)){input.transferTo(output);}output.closeEntry();
                }
            }
        }
        var success=launcher(plugin);assertEquals(0,success.status,success.stderr);assertTrue(HecProtocol.JSON.readTree(success.stdout).has("output_schema"));
        Files.move(jar,jar.resolveSibling("valid.jar"));Files.writeString(jar,"invalid-jar-private-path");assertBootstrapFailure(launcher(plugin));
        Files.delete(jar);Files.move(jar.resolveSibling("valid.jar"),jar);
        Files.delete(home.resolve("logstash-core/lib/jars"));Files.createDirectory(home.resolve("logstash-core/lib/jars"));assertBootstrapFailure(launcher(plugin));
        Files.delete(home.resolve("jdk"));Files.createDirectories(home.resolve("jdk/bin"));Files.writeString(home.resolve("jdk/bin/java"),"#!/bin/sh\nprintf '%s\\n' 'unsupported-java-private-path' >&2\nexit 1\n");Files.setPosixFilePermissions(home.resolve("jdk/bin/java"),PosixFilePermissions.fromString("rwx------"));assertBootstrapFailure(launcher(plugin));
    }
    Cli launcher(Path plugin)throws Exception{
        Process process=new ProcessBuilder("/bin/sh",plugin.resolve("lib/splunk-hec-inspect").toString(),"--help","--json").start();
        try{assertTrue(process.waitFor(20,TimeUnit.SECONDS));return new Cli(process.exitValue(),new String(process.getInputStream().readAllBytes()),new String(process.getErrorStream().readAllBytes()));}finally{cleanup(process);}
    }
    void assertBootstrapFailure(Cli result)throws Exception{
        assertEquals(70,result.status);assertEquals("",result.stdout);var error=HecProtocol.JSON.readTree(result.stderr);assertEquals("runtime_unavailable",error.get("error").get("code").asText());assertFalse(result.stderr.contains("private-path"));assertFalse(result.stderr.contains(root.toString()));
    }
    @Test void terminatingLauncherReapsItsJavaLockHolder()throws Exception{
        Path spool=seed("signal");Path home=root.resolve("signal-runtime"),plugin=home.resolve("plugin");
        Files.createDirectories(home.resolve("jdk/bin"));Files.createDirectories(home.resolve("logstash-core/lib/jars"));
        Files.createDirectories(plugin.resolve("lib"));Files.createDirectories(plugin.resolve("vendor/jars"));
        Files.copy(Path.of("lib/splunk-hec-inspect"),plugin.resolve("lib/splunk-hec-inspect"));
        Files.writeString(plugin.resolve("VERSION"),"0.4.0\n");Files.write(plugin.resolve("vendor/jars/logstash-input-splunk_hec-0.4.0.jar"),new byte[0]);
        Path fake=home.resolve("jdk/bin/java");
        Files.writeString(fake,"#!/bin/sh\nexec \"$INSPECT_TEST_JAVA\" -cp \"$INSPECT_TEST_CP\" org.logstashplugins.hec.S2SAssemblyInspectorTest \"$INSPECT_TEST_SPOOL\" shared\n");
        Files.setPosixFilePermissions(fake,PosixFilePermissions.fromString("rwx------"));
        var command=new ProcessBuilder("/bin/sh",plugin.resolve("lib/splunk-hec-inspect").toString(),"--json");
        command.environment().putAll(Map.of("LOGSTASH_HOME",home.toString(),"INSPECT_TEST_JAVA",Path.of(System.getProperty("java.home"),"bin/java").toString(),"INSPECT_TEST_CP",classpath(),"INSPECT_TEST_SPOOL",spool.toString()));
        Process process=command.start();
        try{
            var ready=java.util.concurrent.CompletableFuture.supplyAsync(()->{try{return process.inputReader().readLine();}catch(IOException e){throw new UncheckedIOException(e);}});
            assertEquals("ready",ready.get(10,TimeUnit.SECONDS));
            process.destroy();assertTrue(process.waitFor(10,TimeUnit.SECONDS));
            released(spool);
        }finally{cleanup(process);}
    }
}
