package org.logstashplugins.hec;

import java.nio.file.*;
import java.nio.channels.*;
import java.util.*;

/** Development-only isolated-copy production-recovery oracle and Java lock peer. Never shipped. */
public final class InspectionProbe {
    public static void main(String[] args)throws Exception{
        Path path=Path.of(args[1]);
        if(args[0].equals("released")){
            try(var file=FileChannel.open(path.resolve("lock"),StandardOpenOption.READ);var lock=file.tryLock(0,Long.MAX_VALUE,true)){if(lock==null)throw new IllegalStateException("lock retained");System.out.println("released");}return;
        }
        if(args[0].equals("write-refused")){
            try(var ignored=FileChannel.open(path.resolve("lock"),StandardOpenOption.WRITE)){throw new IllegalStateException("mount is writable");}
            catch(java.nio.file.FileSystemException expected){System.out.println("read-only");}return;
        }
        if(args[0].equals("inventory")){
            var result=new TreeMap<String,Object>();
            try(var files=Files.walk(path)){
                for(Path file:files.toList()){
                    var attrs=Files.readAttributes(file,java.nio.file.attribute.PosixFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
                    result.put(path.relativize(file).toString(),Map.of("mode",Files.getAttribute(file,"unix:mode",LinkOption.NOFOLLOW_LINKS),"mtime",attrs.lastModifiedTime().toInstant().toString(),"size",attrs.size(),"identity",attrs.fileKey().toString(),
                        "hash",attrs.isRegularFile()?TokenStore.fingerprint(Files.readAllBytes(file)):attrs.isSymbolicLink()?Files.readSymbolicLink(file).toString():"directory/special"));
                }
            }
            System.out.println(HecProtocol.JSON.writeValueAsString(result));return;
        }
        if(args[0].equals("compact")){
            try(var store=new S2SAssemblyStore(path,JournalProbe.QUOTA)){
                var state=S2SStreamAssembler.recoveryMapper(JournalProbe.QUOTA).readValue(store.recover(),S2SStreamAssembler.State.class);store.initialize(state);store.compact();
            }return;
        }
        if(args[0].equals("append")){
            try(var assembly=JournalProbe.open(path)){
                var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);var state=(S2SStreamAssembler.State)field.get(assembly);
                JournalProbe.accept(assembly,"source",state.pending().values().iterator().next().offset(),"continued");
            }return;
        }
        if(args[0].equals("lock")){
            boolean shared=args[2].equals("shared");
            try(var file=FileChannel.open(path.resolve("lock"),shared?StandardOpenOption.READ:StandardOpenOption.WRITE);var lock=file.lock(0,Long.MAX_VALUE,shared)){
                System.out.println("ready "+ProcessHandle.current().pid());System.out.flush();Thread.sleep(60000);
            }return;
        }
        try(var assembly=JournalProbe.open(path)){
            var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);var state=(S2SStreamAssembler.State)field.get(assembly);
            field=S2SStreamAssembler.class.getDeclaredField("store");field.setAccessible(true);var store=field.get(assembly);
            var sequence=S2SAssemblyStore.class.getDeclaredField("sequence");sequence.setAccessible(true);
            var generation=S2SAssemblyStore.class.getDeclaredField("generation");generation.setAccessible(true);
            var pointer=S2SStreamAssembler.recoveryMapper(4096).readValue(S2SAssemblyReader.checked(Files.readAllBytes(path.resolve("current-v3"))),S2SAssemblyStore.Pointer.class);
            System.out.println(HecProtocol.JSON.writeValueAsString(Map.of("pending",state.pending().size(),"outbox",state.outbox().size(),"receipts",state.receipts().size(),
                "blocked",state.blocked(),"contributions",state.pending().values().stream().mapToLong(p->p.contributions().size()).sum(),"sequence",sequence.getLong(store),"generation",generation.getLong(store),"snapshot_sequence",pointer.sequence())));
        }
    }
}
