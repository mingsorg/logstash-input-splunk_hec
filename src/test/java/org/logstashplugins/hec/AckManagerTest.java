package org.logstashplugins.hec;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

class AckManagerTest {
    @TempDir Path dir;
    TokenStore.Token token(boolean cleanup)throws Exception{
        return new TokenStore(null,"[{\"token\":\"one\",\"useACK\":true,\"ackIdleCleanup\":"+cleanup+",\"maxIdleTime\":1}]",s->{}).authenticate("Splunk one",null);
    }
    @Test void pendingConsumeDuplicatesIsolationAndConcurrentPolls()throws Exception{
        var token=token(false);
        try(AckManager a=new AckManager(dir)){
            var ticket=a.reserve(token,"channel");
            assertFalse(a.poll(token,"channel",List.of(ticket.id())).get("0"));
            a.finish(ticket,true);
            assertFalse(a.poll(token,"wrong",List.of(ticket.id())).get("0"));
            ExecutorService pool=Executors.newFixedThreadPool(2);
            try{
                var first=pool.submit(()->a.poll(token,"channel",List.of(ticket.id(),ticket.id())).get("0"));
                var second=pool.submit(()->a.poll(token,"channel",List.of(ticket.id())).get("0"));
                assertNotEquals(first.get(),second.get());
            }finally{pool.shutdownNow();}
            assertFalse(a.poll(token,"channel",List.of(ticket.id())).get("0"));
        }
    }
    @Test void noStaleAliasAcrossRestartOrChannelRecreation()throws Exception{
        var token=token(true);long old;
        try(AckManager a=new AckManager(dir)){var ticket=a.reserve(token,"channel");old=ticket.id();a.finish(ticket,true);}
        try(AckManager a=new AckManager(dir)){
            var ticket=a.reserve(token,"channel");assertTrue(ticket.id()>old);a.finish(ticket,true);
            assertFalse(a.poll(token,"channel",List.of(old)).get(Long.toString(old)));
        }
        Files.write(dir.resolve("ack-high-water-v1"),new byte[]{1});
        assertThrows(java.io.IOException.class,()->new AckManager(dir));
    }
    @Test void exhaustionBeforeEnqueueAndPinnedIdleCleanup()throws Exception{
        AtomicLong time=new AtomicLong();var token=token(true);
        try(AckManager a=new AckManager(dir,1,1,1,time::get)){
            var ticket=a.reserve(token,"channel");time.set(2_000_000_000L);
            assertThrows(HecException.class,()->a.reserve(token,"another"));
            a.finish(ticket,true);time.addAndGet(2_000_000_000L);
            var next=a.reserve(token,"another");assertNotEquals(ticket.id(),next.id());a.finish(next,false);
        }
    }
}
