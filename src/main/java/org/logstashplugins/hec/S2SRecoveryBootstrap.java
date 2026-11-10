package org.logstashplugins.hec;

import java.io.*;

/** JDK-only installed boundary; uncontrolled VM/dependency diagnostics never reach operator output. */
public final class S2SRecoveryBootstrap {
    public static void main(String[] args){
        int status=70;
        try{
            Class.forName("com.fasterxml.jackson.databind.ObjectMapper");
            Class.forName("org.logstash.Timestamp");Class.forName("org.joda.time.ReadableInstant");
            var errors=new ByteArrayOutputStream();
            status=S2SAssemblyRecovery.run(args,System.out,new PrintStream(errors));
            if(status!=70)try(var diagnostics=new FileOutputStream("/dev/fd/3")){errors.writeTo(diagnostics);}
        }catch(LinkageError|Exception error){status=70;}
        System.exit(status);
    }
    private S2SRecoveryBootstrap(){}
}
