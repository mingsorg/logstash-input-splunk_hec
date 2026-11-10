package org.logstashplugins.hec;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.*;

/** Offline lossless retained-state transfer. Never starts an assembler or recovers source storage. */
public final class S2SAssemblyRecovery {
    static final long MAX_ARCHIVE=S2SAssemblyStore.SAFETY_MAXIMUM+65536;
    static final int MAX_HISTORY=16;
    record Source(String format,String authority,Long generation,Long snapshot_sequence,Long sequence) {}
    record Range(long offset,long length) {}
    record Completeness(String classification,Range omitted_range) {}
    record Origin(Source source,Completeness completeness,Origin previous) {}
    record Payload(Origin origin,S2SStreamAssembler.State state) {}
    record Archive(int schema_version,long byte_count,String sha256,Payload payload) {}
    private static ObjectMapper mapper(){
        var mapper=S2SAssemblyInspector.mapper().enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
        var text=mapper.coercionConfigFor(com.fasterxml.jackson.databind.type.LogicalType.Textual);
        for(var shape:List.of(com.fasterxml.jackson.databind.cfg.CoercionInputShape.Integer,com.fasterxml.jackson.databind.cfg.CoercionInputShape.Float,
                com.fasterxml.jackson.databind.cfg.CoercionInputShape.Boolean))text.setCoercion(shape,com.fasterxml.jackson.databind.cfg.CoercionAction.Fail);
        return mapper;
    }
    private static S2SAssemblyInspector.Refusal corrupt(){return new S2SAssemblyInspector.Refusal(3,"corrupt_state");}
    private static void validate(Origin origin,int depth)throws IOException{
        if(depth>MAX_HISTORY)throw new S2SAssemblyReader.BudgetException();
        if(origin==null||origin.source()==null||origin.completeness()==null)throw corrupt();
        var source=origin.source();var complete=origin.completeness();
        if("v2".equals(source.format())){
            if(!"original_v2".equals(source.authority())||source.generation()!=null||source.snapshot_sequence()!=null||source.sequence()!=null||complete.omitted_range()!=null||origin.previous()!=null)throw corrupt();
        }else if("v3".equals(source.format())){
            if(!"published_v3".equals(source.authority())||source.generation()==null||source.generation()<1||source.snapshot_sequence()==null||source.snapshot_sequence()<0||
                source.sequence()==null||source.sequence()<source.snapshot_sequence())throw corrupt();
        }else throw corrupt();
        if(origin.previous()!=null)validate(origin.previous(),depth+1);
        var range=complete.omitted_range();
        if(range!=null&&(range.offset()<0||range.length()<1||range.offset()>S2SAssemblyReader.HISTORY||range.length()>S2SAssemblyReader.HISTORY-range.offset()))throw corrupt();
        boolean inherited=origin.previous()!=null&&!origin.previous().completeness().classification().equals("complete");
        if("complete".equals(complete.classification())){if(range!=null||inherited)throw corrupt();}
        else if(!"incomplete_prefix".equals(complete.classification())||range==null&&!inherited)throw corrupt();
    }
    static Origin readOrigin(byte[] bytes)throws IOException{
        var origin=mapper().readValue(S2SAssemblyReader.checked(bytes),Origin.class);validate(origin,0);return origin;
    }
    private static Origin origin(S2SAssemblyInspector.Result result)throws IOException{
        var summary=result.summary();
        var previous=(Origin)summary.get("recovery_origin");
        @SuppressWarnings("unchecked") var suffix=(Map<String,Object>)summary.get("incomplete_suffix");
        Range range=suffix==null?null:new Range(((Number)suffix.get("offset")).longValue(),((Number)suffix.get("length")).longValue());
        var origin=new Origin(new Source((String)summary.get("format"),(String)summary.get("authority"),(Long)summary.get("generation"),
            (Long)summary.get("snapshot_sequence"),(Long)summary.get("sequence")),new Completeness(result.status()==0?"complete":"incomplete_prefix",range),previous);
        validate(origin,0);return origin;
    }
    static Archive readArchive(byte[] bytes)throws IOException{
        if(bytes.length>MAX_ARCHIVE)throw new S2SAssemblyReader.BudgetException();
        // Preflight collection/token work before databinding, using the same inspection budget.
        var bounded=mapper();
        // Missing fields are refused as well as unknown/duplicate fields, coercions and trailing input.
        var archive=bounded.readValue(S2SAssemblyInspector.json(bytes,bounded),Archive.class);
        if(archive.schema_version()!=1||archive.payload()==null||archive.sha256()==null||!archive.sha256().matches("[a-f0-9]{64}"))throw corrupt();
        validate(archive.payload().origin(),0);
        new S2SAssemblyReader.Validation().validate(archive.payload().state());
        byte[] payload=HecProtocol.JSON.writeValueAsBytes(archive.payload());
        if(payload.length!=archive.byte_count()||!TokenStore.fingerprint(payload).equals(archive.sha256()))throw corrupt();
        return archive;
    }
    private static Map<String,Object> summary(String command,Archive archive,long archiveBytes){
        var state=archive.payload().state();var result=new LinkedHashMap<String,Object>();
        result.put("schema_version",1);result.put("command",command);result.put("classification",archive.payload().origin().completeness().classification());
        result.put("restart_compatibility","not_evaluated");result.put("origin",archive.payload().origin());
        result.put("byte_count",archive.byte_count());result.put("sha256",archive.sha256());result.put("archive_bytes",archiveBytes);
        result.put("pending",state.pending().size());result.put("outbox",state.outbox().size());result.put("receipts",state.receipts().size());result.put("blocked",state.blocked());
        result.put("contributions",state.pending().values().stream().mapToLong(p->p.contributions().size()).sum());return result;
    }
    static S2SAssemblyInspector.Result export(Path source,Path output,S2SAssemblyInspector.Faults faults)throws IOException{
        Path from=source.toAbsolutePath().normalize(),to=output.toAbsolutePath().normalize();
        if(to.startsWith(from)||from.startsWith(to))throw S2SSecureFiles.unsafe();
        return S2SAssemblyInspector.withLocked(source,faults,(result,verify,directoryKey)->{
            if(result.state()==null)throw corrupt();
            var payload=new Payload(origin(result),result.state());byte[] covered=HecProtocol.JSON.writeValueAsBytes(payload);
            var archive=new Archive(1,covered.length,TokenStore.fingerprint(covered),payload);
            byte[] bytes=HecProtocol.JSON.writeValueAsBytes(archive);if(bytes.length>MAX_ARCHIVE)throw new S2SAssemblyReader.BudgetException();
            S2SAssemblyInspector.json(bytes,mapper()); // Archive wrappers count toward the rebuild depth/token budget too.
            verify.run();
            try(var parent=new S2SSecureFiles.Directories(output.toAbsolutePath().getParent())){
                for(var ancestor:parent.chain)if(directoryKey.equals(ancestor.getFileAttributeView(java.nio.file.attribute.PosixFileAttributeView.class).readAttributes().fileKey()))throw S2SSecureFiles.unsafe();
                S2SSecureFiles.writeNew(parent,output.getFileName(),bytes,faults,"archive");verify.run();
            }catch(S2SAssemblyInspector.Refusal error){throw error;}
            catch(IOException error){throw S2SSecureFiles.unsafe();}
            return new S2SAssemblyInspector.Result(result.status(),summary("export",archive,bytes.length));
        });
    }
    static S2SAssemblyInspector.Result rebuild(Path input,Path destination,S2SAssemblyInspector.Faults faults)throws IOException{
        Path from=input.toAbsolutePath().normalize(),to=destination.toAbsolutePath().normalize();
        if(from.startsWith(to)||to.startsWith(from))throw S2SSecureFiles.unsafe();
        byte[] bytes=S2SSecureFiles.input(input,MAX_ARCHIVE,faults);
        Archive archive;
        try{archive=readArchive(bytes);}
        catch(S2SAssemblyReader.BudgetException|com.fasterxml.jackson.core.exc.StreamConstraintsException error){throw new S2SAssemblyInspector.Refusal(5,"budget_exceeded");}
        catch(IOException|IllegalArgumentException|NullPointerException error){throw corrupt();}
        byte[] origin=HecProtocol.JSON.writeValueAsBytes(archive.payload().origin());
        if(origin.length>16384-65)throw new S2SAssemblyInspector.Refusal(5,"budget_exceeded");
        try(var target=new S2SSecureFiles.Destination(destination,faults)){
            S2SAssemblyStore.publishRecovered(target,archive.payload().state(),origin,faults);
        }
        return new S2SAssemblyInspector.Result(archive.payload().origin().completeness().classification().equals("complete")?0:2,summary("rebuild",archive,bytes.length));
    }
    static Map<String,Object> originSchema(){
        return originSchema(0);
    }
    private static Map<String,Object> originSchema(int depth){
        // Bounded recursive provenance is also fully validated by the archive reader.
        var nullable=Map.of("type",List.of("integer","null"),"minimum",0);
        var source=Map.of("type","object","additionalProperties",false,"required",List.of("format","authority","generation","snapshot_sequence","sequence"),"properties",Map.of(
            "format",Map.of("enum",List.of("v2","v3")),"authority",Map.of("enum",List.of("original_v2","published_v3")),"generation",nullable,"snapshot_sequence",nullable,"sequence",nullable));
        var range=Map.of("type",List.of("object","null"),"additionalProperties",false,"required",List.of("offset","length"),"properties",Map.of("offset",Map.of("type","integer","minimum",0),"length",Map.of("type","integer","minimum",1)));
        return Map.of("type","object","additionalProperties",false,"required",List.of("source","completeness","previous"),"properties",Map.of("source",source,"completeness",Map.of("type","object","additionalProperties",false,
            "required",List.of("classification","omitted_range"),"properties",Map.of("classification",Map.of("enum",List.of("complete","incomplete_prefix")),"omitted_range",range)),
            "previous",depth==MAX_HISTORY?Map.of("type","null"):Map.of("anyOf",List.of(Map.of("type","null"),originSchema(depth+1)))));
    }
    private static Map<String,Object> help(){
        var properties=new LinkedHashMap<String,Object>();properties.put("schema_version",Map.of("const",1));properties.put("command",Map.of("enum",List.of("export","rebuild")));
        properties.put("classification",Map.of("enum",List.of("complete","incomplete_prefix")));properties.put("restart_compatibility",Map.of("const","not_evaluated"));properties.put("origin",originSchema());
        for(String field:List.of("byte_count","archive_bytes","pending","outbox","receipts","contributions"))properties.put(field,Map.of("type","integer","minimum",0));
        properties.put("sha256",Map.of("type","string","pattern","^[a-f0-9]{64}$"));properties.put("blocked",Map.of("type","boolean"));
        return Map.of("schema_version",1,"command","splunk-hec-recover","usage",List.of("export --assembly-directory SRC --output ARCHIVE [--json]","rebuild --archive ARCHIVE --assembly-directory NEW [--json]"),
            "argument_schema",Map.of("oneOf",List.of(arguments("export",List.of("--assembly-directory","--output")),arguments("rebuild",List.of("--archive","--assembly-directory")))),
            "output_schema",Map.of("type","object","additionalProperties",false,"required",List.copyOf(properties.keySet()),"properties",properties),
            "error_schema",Map.of("type","object","required",List.of("schema_version","error"),"additionalProperties",false,"properties",Map.of("schema_version",Map.of("const",1),"error",Map.of("type","object","additionalProperties",false,"required",List.of("code","message"),"properties",Map.of("code",Map.of("type","string"),"message",Map.of("type","string"))))),
            "exit_codes",Map.of("0","complete","2","incomplete prefix","3","corrupt/unsupported","4","locked","5","storage/budget","64","usage","70","runtime/internal"),
            "storage","Linux/JDK 21, trusted private local storage and private existing output parents required. Source is locked read-only. Archive contains sensitive payloads. Checksums are integrity, not authenticity. Rebuild does not activate state; restart compatibility is not evaluated.");
    }
    private static Map<String,Object> arguments(String command,List<String> required){
        var properties=new LinkedHashMap<String,Object>();for(String field:required)properties.put(field,Map.of("type","string","minLength",1));properties.put("--json",Map.of("type","boolean"));
        properties.put("command",Map.of("const",command));var fields=new ArrayList<>(required);fields.add("command");
        return Map.of("type","object","additionalProperties",false,"required",fields,"properties",properties);
    }
    static int run(String[] args,PrintStream out,PrintStream err){return run(args,out,err,S2SAssemblyInspector.NO_FAULTS);}
    static int run(String[] args,PrintStream out,PrintStream err,S2SAssemblyInspector.Faults faults){
        boolean json=Arrays.asList(args).contains("--json");
        try{
            var values=new HashMap<String,String>();String command=null;boolean wantsHelp=false;var seen=new HashSet<String>();
            for(int i=0;i<args.length;i++){
                String flag=args[i];if(!seen.add(flag))throw new S2SAssemblyInspector.Refusal(64,"usage");
                switch(flag){
                    case "export","rebuild" -> {if(command!=null||i!=0)throw new S2SAssemblyInspector.Refusal(64,"usage");command=flag;}
                    case "--json" -> {}
                    case "--help" -> wantsHelp=true;
                    case "--assembly-directory","--output","--archive" -> {if(++i==args.length||args[i].isBlank()||args[i].startsWith("--"))throw new S2SAssemblyInspector.Refusal(64,"usage");values.put(flag,args[i]);}
                    default -> throw new S2SAssemblyInspector.Refusal(64,"usage");
                }
            }
            if(wantsHelp){if(!values.isEmpty())throw new S2SAssemblyInspector.Refusal(64,"usage");print(help(),json,out);return 0;}
            if(command==null||!values.keySet().equals(command.equals("export")?Set.of("--assembly-directory","--output"):Set.of("--assembly-directory","--archive")))throw new S2SAssemblyInspector.Refusal(64,"usage");
            var directory=Path.of(values.get("--assembly-directory"));
            var result=command.equals("export")?export(directory,Path.of(values.get("--output")),faults):rebuild(Path.of(values.get("--archive")),directory,faults);
            print(result.summary(),json,out);if(out.checkError())throw S2SSecureFiles.unsafe();return result.status();
        }catch(S2SAssemblyInspector.Refusal error){return error(error.status,error.code,json,err);}
        catch(InvalidPathException error){return error(64,"usage",json,err);}
        catch(S2SAssemblyReader.BudgetException|com.fasterxml.jackson.core.exc.StreamConstraintsException error){return error(5,"budget_exceeded",json,err);}
        catch(IOException error){return error(5,"unsafe_storage",json,err);}
        catch(RuntimeException error){return error(70,"internal",json,err);}
    }
    private static void print(Map<String,Object> value,boolean json,PrintStream out)throws IOException{
        if(json)out.println(HecProtocol.JSON.writeValueAsString(value));else value.forEach((key,item)->out.println(key+": "+item));
    }
    private static int error(int status,String code,boolean json,PrintStream err){
        String message=switch(status){case 64 -> "Invalid recovery arguments; use --help.";case 3 -> "Retained state or archive is corrupt, incomplete or unsupported.";
            case 4 -> "Assembly storage is locked or compatible shared locking is unavailable.";case 5 -> "Recovery storage operation or resource budget failed.";default -> "Recovery runtime failed.";};
        if(json)err.println("{\"schema_version\":1,\"error\":{\"code\":\""+code+"\",\"message\":\""+message+"\"}}");else err.println(code+": "+message);return status;
    }
    public static void main(String[] args){System.exit(run(args,System.out,System.err));}
    private S2SAssemblyRecovery(){}
}
