package org.logstashplugins.hec;

import java.io.*;

/** JDK-only boundary: the shell hides VM/linker diagnostics; only controlled application stderr uses fd 3. */
public final class S2SInspectionBootstrap {
    public static void main(String[] args){
        int status=70;
        try{
            // Resolve dependencies before touching a spool, even for --help.
            Class.forName("com.fasterxml.jackson.databind.ObjectMapper");
            Class.forName("org.logstash.Timestamp");
            Class.forName("org.joda.time.ReadableInstant");
            var errors=new ByteArrayOutputStream();
            status=S2SAssemblyInspector.run(args,System.in,System.out,new PrintStream(errors));
            if(status!=70)try(var diagnostics=new FileOutputStream("/dev/fd/3")){errors.writeTo(diagnostics);}
        }catch(LinkageError|Exception error){status=70;}
        System.exit(status);
    }
    private S2SInspectionBootstrap(){}
}
