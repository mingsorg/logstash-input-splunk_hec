package org.logstashplugins.hec;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

/** Offline installed entrypoint. All spool descriptors are opened READ + NOFOLLOW_LINKS. */
public final class S2SAssemblyInspector {
    static final int MAX_ENTRIES=256, MAX_RECORDS=100000, MAX_TOKENS=1000000;
    static final long MAX_INPUT=65536;
    static final class Refusal extends IOException {
        final int status;final String code;
        Refusal(int status,String code){super(message(code));this.status=status;this.code=code;}
    }
    private static String message(String code){return switch(code){
        case "usage" -> "Invalid inspection arguments or input; use --help.";
        case "locked" -> "Assembly storage is locked by another owner.";
        case "locking_unsupported" -> "Compatible shared Java locking is unavailable.";
        case "unsafe_storage" -> "Assembly storage is unsafe, changed, absent or unreadable.";
        case "budget_exceeded" -> "Assembly inspection resource budget exceeded.";
        case "corrupt_state" -> "Assembly state is corrupt or unsupported.";
        default -> "Assembly inspection failed internally.";
    };}
    record Result(int status,Map<String,Object> summary) {}
    interface Faults {void at(String boundary)throws IOException;}
    static final Faults NO_FAULTS=boundary->{};
    private record Identity(Object key,long size,java.nio.file.attribute.FileTime mtime,Set<PosixFilePermission> permissions) {}

    /** Descriptor-relative traversal pins every directory component and refuses unsupported providers. */
    private static final class Storage implements AutoCloseable {
        final List<SecureDirectoryStream<Path>> chain=new ArrayList<>();
        final SecureDirectoryStream<Path> directory;
        final Path path;
        final Identity directoryIdentity;
        final Faults faults;
        Map<Path,Identity> before;
        Storage(Path supplied,Faults faults)throws IOException{
            this.faults=faults;
            path=supplied.toAbsolutePath();
            try{
                var root=Files.newDirectoryStream(path.getRoot());
                if(!(root instanceof SecureDirectoryStream<Path> secure)){root.close();throw new Refusal(5,"unsafe_storage");}
                chain.add(secure);
                for(Path component:path){
                    if(component.toString().equals(".."))throw new Refusal(5,"unsafe_storage");
                    if(component.toString().equals("."))continue;
                    secure=secure.newDirectoryStream(component,LinkOption.NOFOLLOW_LINKS);chain.add(secure);
                }
                directory=secure;
                var attrs=directory.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
                if(attrs.fileKey()==null||attrs.permissions().stream().anyMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")))throw new Refusal(5,"unsafe_storage");
                directoryIdentity=new Identity(attrs.fileKey(),attrs.size(),attrs.lastModifiedTime(),Set.copyOf(attrs.permissions()));
                before=Map.of(Path.of("lock"),identity(Path.of("lock")));
            }catch(IOException error){close();throw S2SSecureFiles.unsafe();}
            catch(RuntimeException error){close();throw new Refusal(5,"unsafe_storage");}
        }
        Identity identity(Path name)throws IOException{
            var attrs=S2SSecureFiles.attributes(directory,name);
            if(!attrs.isRegularFile()||attrs.fileKey()==null)throw new Refusal(5,"unsafe_storage");
            return new Identity(attrs.fileKey(),attrs.size(),attrs.lastModifiedTime(),Set.copyOf(attrs.permissions()));
        }
        Map<Path,Identity> inventory()throws IOException{
            var values=new HashMap<Path,Identity>();long bytes=0;
            // SecureDirectoryStream has a single-use iterator. Open a second pinned descriptor for each inventory.
            try(var entries=directory.newDirectoryStream(Path.of("."),LinkOption.NOFOLLOW_LINKS)){
                faults.at("storage.enumerate");
                for(Path entry:entries){
                    if(values.size()>=MAX_ENTRIES)throw new Refusal(5,"budget_exceeded");
                    Path name=entry.getFileName();var id=identity(name);
                    if(id.size>S2SAssemblyReader.HISTORY+65)throw new Refusal(5,"budget_exceeded");
                    bytes=Math.addExact(bytes,id.size);
                    if(bytes>S2SAssemblyReader.PHYSICAL)throw new Refusal(5,"budget_exceeded");
                    values.put(name,id);
                }
            }catch(Refusal error){throw error;}
            catch(IOException|DirectoryIteratorException error){throw S2SSecureFiles.unsafe();}
            return values;
        }
        FileChannel open(String name,long maximum)throws IOException{
            Path relative=Path.of(name);var expected=before.get(relative);
            if(expected==null)throw new Refusal(5,"unsafe_storage");
            if(expected.size>maximum)throw new Refusal(5,"budget_exceeded");
            if(!expected.equals(identity(relative)))throw new Refusal(5,"unsafe_storage");
            try{
                faults.at("storage.open");
                var attrs=S2SSecureFiles.attributes(directory,relative);
                if(!expected.equals(new Identity(attrs.fileKey(),attrs.size(),attrs.lastModifiedTime(),Set.copyOf(attrs.permissions()))))throw S2SSecureFiles.unsafe();
                return S2SSecureFiles.regular(directory,relative,attrs,faults,"storage",this::verifyDirectories);
            }catch(Refusal error){throw error;}
            catch(IOException error){throw S2SSecureFiles.unsafe();}
        }
        boolean has(String name){return before.containsKey(Path.of(name));}
        byte[] bytes(String name,long maximum)throws IOException{
            try(var file=open(name,maximum)){
                // Allocate only the size admitted by the locked inventory. A
                // non-cooperating process can grow an inode after it was pinned.
                long admitted=before.get(Path.of(name)).size();
                faults.at("storage.read");byte[] bytes=new byte[(int)admitted];S2SAssemblyReader.read(file,0,bytes);return bytes;
            }catch(Refusal error){throw error;}
            catch(IOException error){throw S2SSecureFiles.unsafe();}
        }
        long total(){return before.values().stream().mapToLong(Identity::size).sum();}
        void unchanged()throws IOException{
            try{
            if(!before.equals(inventory()))throw new Refusal(5,"unsafe_storage");
            var attrs=directory.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
            if(!directoryIdentity.equals(new Identity(attrs.fileKey(),attrs.size(),attrs.lastModifiedTime(),Set.copyOf(attrs.permissions()))))throw new Refusal(5,"unsafe_storage");
            verifyDirectories();
            }catch(Refusal error){throw error;}
            catch(IOException error){throw S2SSecureFiles.unsafe();}
        }
        void verifyDirectories()throws IOException{
            int index=0;
            for(Path component:path){
                if(component.toString().equals("."))continue;
                var named=S2SSecureFiles.attributes(chain.get(index),component);index++;
                var pinned=chain.get(index).getFileAttributeView(BasicFileAttributeView.class).readAttributes();
                if(!named.isDirectory()||!Objects.equals(named.fileKey(),pinned.fileKey()))throw new Refusal(5,"unsafe_storage");
            }
        }
        @Override public void close()throws IOException{
            IOException failure=null;
            for(int i=chain.size()-1;i>=0;i--)try{chain.get(i).close();}catch(IOException error){failure=error;}
            chain.clear();if(failure!=null)throw S2SSecureFiles.unsafe();
        }
    }
    private static ObjectMapper mapper(){
        var mapper=S2SStreamAssembler.recoveryMapper(S2SAssemblyReader.HISTORY);
        mapper.getFactory().setStreamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64)
            .maxStringLength((int)S2SAssemblyStore.SAFETY_MAXIMUM).maxNumberLength(1024).build());
        return mapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT).disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);
    }
    /** Preflight tokens before databinding collections; aggregate parser work is also bounded by physical bytes. */
    private static byte[] json(byte[] payload,ObjectMapper mapper)throws IOException{
        try(var parser=mapper.createParser(payload)){
            int tokens=0;while(parser.nextToken()!=null)if(++tokens>MAX_TOKENS)throw new S2SAssemblyReader.BudgetException();
        }
        return payload;
    }
    private static final class InspectionMapper extends ObjectMapper {
        private final ObjectMapper bounded=mapper();
        @Override public <T> T readValue(byte[] bytes,Class<T> type)throws IOException{return bounded.readValue(json(bytes,bounded),type);}
        byte[] readPayload(byte[] bytes)throws IOException{return S2SAssemblyReader.checked(bytes);}
    }
    static Result inspect(Path path)throws IOException{
        return inspect(path,NO_FAULTS);
    }
    static Result inspect(Path path,Faults faults)throws IOException{
        try(var storage=new Storage(path,faults);var lockFile=storage.open("lock",S2SAssemblyReader.HISTORY)){
            FileLock acquired;
            try{acquired=lockFile.tryLock(0,Long.MAX_VALUE,true);}
            catch(OverlappingFileLockException error){throw new Refusal(4,"locked");}
            catch(IOException|UnsupportedOperationException error){throw new Refusal(4,"locking_unsupported");}
            if(acquired==null)throw new Refusal(4,"locked");
            try(var lock=acquired){
                if(!lock.isShared())throw new Refusal(4,"locking_unsupported");
                var lockIdentity=storage.before.get(Path.of("lock"));storage.before=storage.inventory();
                if(!lockIdentity.equals(storage.before.get(Path.of("lock"))))throw new Refusal(5,"unsafe_storage");
                try{return summarize(storage);}
                finally{storage.unchanged();}
            }
        }catch(Refusal error){throw error;}
        catch(S2SAssemblyReader.BudgetException|com.fasterxml.jackson.core.exc.StreamConstraintsException error){throw new Refusal(5,"budget_exceeded");}
        catch(java.nio.file.FileSystemException|S2SAssemblyReader.ReadFailure|DirectoryIteratorException error){throw new Refusal(5,"unsafe_storage");}
        catch(IOException|IllegalArgumentException|NullPointerException error){
            for(Throwable cause=error;cause!=null;cause=cause.getCause())if(cause instanceof S2SAssemblyReader.BudgetException||cause instanceof com.fasterxml.jackson.core.exc.StreamConstraintsException)throw new Refusal(5,"budget_exceeded");
            throw new Refusal(3,"corrupt_state");
        }
    }
    private static Result summarize(Storage storage)throws IOException{
        var mapper=new InspectionMapper();var result=new LinkedHashMap<String,Object>();
        result.put("schema_version",1);result.put("restart_compatibility","not_evaluated");
        result.put("physical_bytes",storage.total());result.put("entries",storage.before.size());
        result.put("backup",storage.has("backup-v2")?"present_not_current":"absent");
        result.put("publication_candidates",storage.before.keySet().stream().filter(p->p.toString().matches("(snapshot|journal)-v3-[0-9]+|pointer-next-v3|backup-next-v2|next")).count());
        String marker="absent";
        if(storage.has("state")){
            long size=storage.before.get(Path.of("state")).size;
            if(size<65){
                byte[] bytes=storage.bytes("state",65);
                marker=Arrays.equals(bytes,S2SAssemblyReader.REFUSAL)?"migrated_v3":Arrays.equals(bytes,S2SAssemblyReader.FRESH_REFUSAL)?"fresh_v3":"invalid";
            }else marker="legacy_snapshot";
        }
        result.put("marker",marker);
        String established="absent";
        if(storage.has("established-v3")){
            if(storage.before.get(Path.of("established-v3")).size!=1)throw new Refusal(3,"corrupt_state");
            if(!Arrays.equals(storage.bytes("established-v3",1),new byte[]{3}))throw new Refusal(3,"corrupt_state");
            established="present_valid";
        }
        result.put("established_marker",established);
        if(storage.has("current-v3")){
            var pointer=S2SAssemblyReader.pointer(mapper.readPayload(storage.bytes("current-v3",4161)),mapper);
            String selectedSnapshot="snapshot-v3-"+pointer.generation(),selectedJournal="journal-v3-"+pointer.generation();
            result.put("publication_candidates",storage.before.keySet().stream().map(Path::toString)
                .filter(name->name.matches("(snapshot|journal)-v3-[0-9]+|pointer-next-v3|backup-next-v2|next"))
                .filter(name->!name.equals(selectedSnapshot)&&!name.equals(selectedJournal)).count());
            var snapshot=S2SAssemblyReader.snapshot(mapper.readPayload(storage.bytes("snapshot-v3-"+pointer.generation(),S2SAssemblyStore.SAFETY_MAXIMUM+4161)),pointer,mapper);
            try(var journal=storage.open("journal-v3-"+pointer.generation(),S2SAssemblyReader.HISTORY)){
                try{storage.faults.at("storage.journal-read");}catch(IOException error){throw S2SSecureFiles.unsafe();}
                var replay=S2SAssemblyReader.replay(journal,snapshot.state(),snapshot.sequence(),mapper,new S2SAssemblyReader.Validation(),MAX_RECORDS);
                result.put("format","v3");result.put("authority","published_v3");result.put("generation",pointer.generation());
                result.put("snapshot_sequence",snapshot.sequence());result.put("sequence",replay.sequence());result.put("transactions",replay.transactions());
                long journalSize=S2SAssemblyReader.size(journal);
                result.put("journal_bytes",journalSize);result.put("journal_prefix_bytes",replay.prefix());
                boolean incomplete=replay.prefix()!=journalSize;
                result.put("incomplete_suffix",incomplete?Map.of("offset",replay.prefix(),"length",journalSize-replay.prefix()):null);
                if(marker.equals("invalid"))throw new Refusal(3,"corrupt_state");
                counts(result,replay.state());result.put("classification",incomplete?"incomplete_suffix":"complete");return new Result(incomplete?2:0,result);
            }
        }
        if(marker.equals("legacy_snapshot")&&established.equals("absent")){
            var state=mapper.readValue(mapper.readPayload(storage.bytes("state",S2SAssemblyStore.SAFETY_MAXIMUM+65)),S2SStreamAssembler.State.class);
            new S2SAssemblyReader.Validation().validate(state);
            result.put("format","v2");result.put("authority","original_v2");result.put("classification","complete");
            result.put("generation",null);result.put("snapshot_sequence",null);result.put("sequence",null);result.put("transactions",0);
            result.put("journal_bytes",0);result.put("journal_prefix_bytes",0);result.put("incomplete_suffix",null);counts(result,state);return new Result(0,result);
        }
        if(marker.equals("invalid"))throw new Refusal(3,"corrupt_state");
        result.put("format","unpublished");result.put("authority","none");
        result.put("classification",!established.equals("absent")||storage.has("backup-v2")?"ambiguous":"incomplete_publication");return new Result(2,result);
    }
    private static void counts(Map<String,Object> result,S2SStreamAssembler.State state){
        result.put("pending",state.pending().size());result.put("outbox",state.outbox().size());result.put("receipts",state.receipts().size());
        result.put("contributions",state.pending().values().stream().mapToLong(p->p.contributions().size()).sum());result.put("blocked",state.blocked());
    }

    private static Map<String,Object> help(){
        var help=new LinkedHashMap<String,Object>();help.put("schema_version",1);help.put("command","splunk-hec-inspect");
        help.put("usage","sh /installed/plugin/lib/splunk-hec-inspect --assembly-directory PATH [--json]");
        help.put("options",List.of("--assembly-directory PATH","--json","--help","--stdin","--input-file PATH"));
        help.put("input_schema",Map.of("type","object","additionalProperties",false,"properties",Map.of("schema_version",Map.of("const",1),"assembly_directory",Map.of("type","string"),"json",Map.of("type","boolean"))));
        var properties=new LinkedHashMap<String,Object>();
        properties.put("schema_version",Map.of("const",1));properties.put("restart_compatibility",Map.of("const","not_evaluated"));
        properties.put("format",Map.of("enum",List.of("v2","v3","unpublished")));
        properties.put("authority",Map.of("enum",List.of("original_v2","published_v3","none")));
        properties.put("classification",Map.of("enum",List.of("complete","incomplete_suffix","incomplete_publication","ambiguous")));
        properties.put("marker",Map.of("enum",List.of("absent","migrated_v3","fresh_v3","legacy_snapshot")));
        properties.put("backup",Map.of("enum",List.of("absent","present_not_current")));
        properties.put("established_marker",Map.of("enum",List.of("absent","present_valid")));
        for(String field:List.of("physical_bytes","entries","publication_candidates","pending","outbox","receipts","contributions","transactions","journal_bytes","journal_prefix_bytes"))properties.put(field,Map.of("type","integer","minimum",0));
        for(String field:List.of("generation","snapshot_sequence","sequence"))properties.put(field,Map.of("type",List.of("integer","null"),"minimum",0));
        properties.put("blocked",Map.of("type","boolean"));
        properties.put("incomplete_suffix",Map.of("type",List.of("object","null"),"additionalProperties",false,"required",List.of("offset","length"),"properties",Map.of("offset",Map.of("type","integer","minimum",0),"length",Map.of("type","integer","minimum",1))));
        var workFields=List.of("pending","outbox","receipts","contributions","transactions","blocked","generation","snapshot_sequence","sequence","journal_bytes","journal_prefix_bytes","incomplete_suffix");
        var legacy=new LinkedHashMap<String,Object>();
        legacy.put("format",Map.of("const","v2"));legacy.put("authority",Map.of("const","original_v2"));legacy.put("classification",Map.of("const","complete"));
        for(String field:List.of("generation","snapshot_sequence","sequence","incomplete_suffix"))legacy.put(field,Map.of("type","null"));
        for(String field:List.of("transactions","journal_bytes","journal_prefix_bytes"))legacy.put(field,Map.of("const",0));
        var published=new LinkedHashMap<String,Object>();
        published.put("format",Map.of("const","v3"));published.put("authority",Map.of("const","published_v3"));published.put("generation",Map.of("type","integer","minimum",1));
        for(String field:List.of("snapshot_sequence","sequence"))published.put(field,Map.of("type","integer","minimum",0));
        var complete=new LinkedHashMap<>(published);complete.put("classification",Map.of("const","complete"));complete.put("incomplete_suffix",Map.of("type","null"));
        var incomplete=new LinkedHashMap<>(published);incomplete.put("classification",Map.of("const","incomplete_suffix"));incomplete.put("incomplete_suffix",Map.of("type","object"));
        var unpublished=Map.of("format",Map.of("const","unpublished"),"authority",Map.of("const","none"),"classification",Map.of("enum",List.of("incomplete_publication","ambiguous")));
        help.put("output_schema",Map.of("type","object","additionalProperties",false,"properties",properties,"required",List.of("schema_version","format","authority","classification","restart_compatibility","physical_bytes","entries","publication_candidates","marker","backup","established_marker"),"oneOf",List.of(
            Map.of("properties",legacy,"required",workFields),Map.of("properties",complete,"required",workFields),Map.of("properties",incomplete,"required",workFields),
            Map.of("properties",unpublished,"not",Map.of("anyOf",workFields.stream().map(field->Map.of("required",List.of(field))).toList())))));
        help.put("error_schema",Map.of("type","object","additionalProperties",false,"required",List.of("schema_version","error"),"properties",Map.of("schema_version",Map.of("const",1),"error",Map.of("type","object","additionalProperties",false,"required",List.of("code","message"),"properties",Map.of("code",Map.of("type","string"),"message",Map.of("type","string"))))));
        help.put("warning_schema",Map.of("type","object","additionalProperties",false,"required",List.of("schema_version","warning"),"properties",Map.of("schema_version",Map.of("const",1),"warning",Map.of("type","object","additionalProperties",false,"required",List.of("code","message"),"properties",Map.of("code",Map.of("const","incomplete_state"),"message",Map.of("const","Only the reported authority is available; storage was not modified."))))));
        help.put("exit_codes",Map.of("0","complete","2","incomplete/ambiguous","3","corrupt/unsupported","4","locked/locking unsupported","5","unsafe/unreadable/budget","64","usage","70","internal"));
        help.put("storage","Requires trusted private local storage, an existing regular lock and compatible shared Java locks. Stop ingestion first. Symlinks and special files are refused. Advisory locks cannot prevent hostile replacement.");
        help.put("precedence","Flags override JSON. --stdin and --input-file are mutually exclusive. Unknown keys and options are rejected.");
        help.put("restart_compatibility","not_evaluated");return help;
    }
    static int run(String[] args,InputStream stdin,PrintStream out,PrintStream err){
        return run(args,stdin,out,err,NO_FAULTS);
    }
    static int run(String[] args,InputStream stdin,PrintStream out,PrintStream err,Faults faults){
        boolean json=Arrays.asList(args).contains("--json");
        try{
            String directory=null,inputFile=null;boolean useStdin=false,wantsHelp=false;
            var seen=new HashSet<String>();
            for(int i=0;i<args.length;i++){
                String flag=args[i];if(!seen.add(flag))throw new Refusal(64,"usage");
                switch(flag){
                    case "--assembly-directory" -> {if(++i==args.length||args[i].isBlank()||args[i].startsWith("--"))throw new Refusal(64,"usage");directory=args[i];}
                    case "--input-file" -> {if(++i==args.length||args[i].isBlank()||args[i].startsWith("--"))throw new Refusal(64,"usage");inputFile=args[i];}
                    case "--stdin" -> useStdin=true;
                    case "--json" -> json=true;
                    case "--help" -> wantsHelp=true;
                    default -> throw new Refusal(64,"usage");
                }
            }
            if(useStdin&&inputFile!=null)throw new Refusal(64,"usage");
            if(wantsHelp){if(json)out.println(HecProtocol.JSON.writeValueAsString(help()));else help().forEach((key,value)->out.println(key+": "+value));return 0;}
            if(useStdin||inputFile!=null){
                byte[] bytes;
                if(useStdin)bytes=stdin.readNBytes((int)MAX_INPUT+1);
                else bytes=S2SSecureFiles.input(Path.of(inputFile),MAX_INPUT,faults);
                if(bytes.length>MAX_INPUT)throw new Refusal(64,"usage");
                JsonNode node;
                try{node=mapper().readTree(bytes);}catch(IOException error){throw new Refusal(64,"usage");}
                if(node==null||!node.isObject())throw new Refusal(64,"usage");
                var keys=node.fieldNames();while(keys.hasNext())if(!Set.of("schema_version","assembly_directory","json").contains(keys.next()))throw new Refusal(64,"usage");
                if(node.has("schema_version")&&(!node.get("schema_version").isIntegralNumber()||!node.get("schema_version").canConvertToInt()||node.get("schema_version").intValue()!=1))throw new Refusal(64,"usage");
                if(node.has("assembly_directory")){if(!node.get("assembly_directory").isTextual())throw new Refusal(64,"usage");if(directory==null)directory=node.get("assembly_directory").textValue();}
                if(node.has("json")){if(!node.get("json").isBoolean())throw new Refusal(64,"usage");json=json||node.get("json").booleanValue();}
            }
            if(directory==null||directory.isBlank())throw new Refusal(64,"usage");
            Result result=inspect(Path.of(directory),faults);
            if(json)out.println(HecProtocol.JSON.writeValueAsString(result.summary));else result.summary.forEach((key,value)->out.println(key+": "+value));
            if(result.status!=0)err.println(json?"{\"schema_version\":1,\"warning\":{\"code\":\"incomplete_state\",\"message\":\"Only the reported authority is available; storage was not modified.\"}}":"Warning: incomplete or ambiguous state; storage was not modified.");
            return result.status;
        }catch(Refusal error){return error(error.status,error.code,json,err);}
        catch(InvalidPathException error){return error(64,"usage",json,err);}
        catch(IOException error){return error(5,"unsafe_storage",json,err);}
        catch(RuntimeException error){return error(70,"internal",json,err);}
    }
    private static int error(int status,String code,boolean json,PrintStream err){
        if(json)err.println("{\"schema_version\":1,\"error\":{\"code\":\""+code+"\",\"message\":\""+message(code)+"\"}}");
        else err.println(code+": "+message(code));return status;
    }
    public static void main(String[] args){System.exit(run(args,System.in,System.out,System.err));}
    private S2SAssemblyInspector(){}
}
