package org.logstashplugins.hec;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;

/** Test-only full-state recovery oracle. Not packaged and never used against the source. */
public final class RecoveryProbe {
    public static void main(String[] args)throws Exception{
        if(args[0].equals("adopt")){System.out.println(HecProtocol.JSON.writeValueAsString(adopt(Path.of(args[1]))));return;}
        try(var store=new S2SAssemblyStore(Path.of(args[0]),S2SAssemblyStore.SAFETY_MAXIMUM)){
            byte[] recovered=store.recover(new S2SAssemblyReader.Validation());
            var state=S2SStreamAssembler.recoveryMapper(S2SAssemblyStore.SAFETY_MAXIMUM).readValue(recovered,S2SStreamAssembler.State.class);
            System.out.println(HecProtocol.JSON.writeValueAsString(state));
        }
    }
    static S2SStreamAssembler.State state(S2SStreamAssembler assembly)throws Exception{
        var field=S2SStreamAssembler.class.getDeclaredField("state");field.setAccessible(true);return (S2SStreamAssembler.State)field.get(assembly);
    }
    static Map<String,Object> adopt(Path path)throws Exception{
        var received=new LinkedBlockingQueue<Map<String,Object>>();var delivered=new ArrayList<Map<String,Object>>();
        List<String> originalIds,finalizedIds;
        try(var assembly=JournalProbe.open(path)){
            var before=state(assembly);originalIds=before.outbox().stream().map(S2SStreamAssembler.Output::id).toList();
            if(before.pending().size()!=1||originalIds.size()!=1||before.blocked())throw new IllegalStateException("adoption fixture mismatch");
            JournalProbe.accept(assembly,"source",0,"START queued\nSTART pending");
            if(!Arrays.equals(HecProtocol.JSON.writeValueAsBytes(before),HecProtocol.JSON.writeValueAsBytes(state(assembly))))throw new IllegalStateException("retained retry not suppressed");
            JournalProbe.accept(assembly,"source",26,"trace");JournalProbe.CLOCK.addAndGet(60001);
            try(var lease=JournalProbe.MEMORY.lease()){assembly.expire(lease);}
            var finalized=state(assembly);finalizedIds=finalized.outbox().stream().map(S2SStreamAssembler.Output::id).toList();
            if(finalizedIds.size()!=2||!finalizedIds.getFirst().equals(originalIds.getFirst())||finalized.outbox().stream().anyMatch(output->!Objects.equals(output.sender(),before.outbox().getFirst().sender())))throw new IllegalStateException("adopted IDs or sender order changed");
            var expected=finalized.outbox().stream().map(output->S2SAssemblyReader.envelope(output.envelope())).toList();
            assembly.start(received::add);
            for(int i=0;i<2;i++){var event=received.poll(10,TimeUnit.SECONDS);if(event==null)throw new IllegalStateException("adoption drain timeout");delivered.add(event);}
            if(!expected.equals(delivered)||!delivered.stream().map(event->event.get("event")).toList().equals(List.of("START queued\n","START pending\ntrace")))throw new IllegalStateException("adoption delivery order changed");
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(assembly.outputCount()!=0&&System.nanoTime()<deadline)Thread.sleep(10);
            if(assembly.outputCount()!=0)throw new IllegalStateException("adoption handoff not committed");
            JournalProbe.accept(assembly,"source",0,"START queued\nSTART pending");JournalProbe.accept(assembly,"source",26,"trace");
            if(assembly.pendingCount()!=0||assembly.outputCount()!=0||!received.isEmpty())throw new IllegalStateException("adoption retry replayed work");
        }
        return Map.of("compatible_adoption",true,"continuation",true,"drained",true,"preserved_ids",true,"sender_order",true,"retry_suppression",true,
            "original_ids",originalIds,"finalized_ids",finalizedIds);
    }
}
