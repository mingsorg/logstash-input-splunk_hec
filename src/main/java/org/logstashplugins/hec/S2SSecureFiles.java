package org.logstashplugins.hec;

import java.io.IOException;
import java.lang.reflect.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Linux/JDK descriptor pins. O_PATH never opens a FIFO/device for I/O; unsupported providers fail closed. */
final class S2SSecureFiles {
    static S2SAssemblyInspector.Refusal unsafe(){return new S2SAssemblyInspector.Refusal(5,"unsafe_storage");}
    static final class Directories implements AutoCloseable {
        final Path path;
        final List<SecureDirectoryStream<Path>> chain=new ArrayList<>();
        final List<Path> names=new ArrayList<>();
        Directories(Path supplied)throws IOException{
            path=supplied.toAbsolutePath();
            try{
                var root=Files.newDirectoryStream(path.getRoot());
                if(!(root instanceof SecureDirectoryStream<Path> secure)){root.close();throw unsafe();}
                chain.add(secure);
                for(Path component:path){
                    if(component.toString().equals(".."))throw unsafe();
                    if(component.toString().equals("."))continue;
                    secure=secure.newDirectoryStream(component,LinkOption.NOFOLLOW_LINKS);chain.add(secure);names.add(component);
                }
            }catch(IOException|RuntimeException error){close();throw unsafe();}
        }
        SecureDirectoryStream<Path> directory(){return chain.getLast();}
        void verify()throws IOException{
            try{
                for(int i=0;i<names.size();i++){
                    var named=attributes(chain.get(i),names.get(i));
                    var pinned=chain.get(i+1).getFileAttributeView(PosixFileAttributeView.class).readAttributes();
                    if(!named.isDirectory()||named.fileKey()==null||!named.fileKey().equals(pinned.fileKey()))throw unsafe();
                }
            }catch(IOException|RuntimeException error){throw unsafe();}
        }
        @Override public void close()throws IOException{
            IOException failure=null;
            for(int i=chain.size()-1;i>=0;i--)try{chain.get(i).close();}catch(IOException error){failure=unsafe();}
            chain.clear();if(failure!=null)throw failure;
        }
    }
    static PosixFileAttributes attributes(SecureDirectoryStream<Path> directory,Path name)throws IOException{
        try{
            var view=directory.getFileAttributeView(name,PosixFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);
            if(view==null)throw unsafe();return view.readAttributes();
        }catch(IOException|RuntimeException error){throw unsafe();}
    }
    private static boolean same(PosixFileAttributes expected,PosixFileAttributes actual){
        return actual.isRegularFile()&&actual.fileKey()!=null&&actual.fileKey().equals(expected.fileKey())&&actual.size()==expected.size()&&
            actual.lastModifiedTime().equals(expected.lastModifiedTime())&&actual.permissions().equals(expected.permissions());
    }
    /** Pins metadata first, verifies inode/type, then reopens only that kernel-owned fd for reading. */
    static FileChannel regular(SecureDirectoryStream<Path> directory,Path name,PosixFileAttributes expected,
                               S2SAssemblyInspector.Faults faults,String family,RunnableIO verify)throws IOException{
        int descriptor=-1;Method close=null;FileChannel channel=null;
        try{
            if(!System.getProperty("os.name").equals("Linux")||!directory.getClass().getName().equals("sun.nio.fs.UnixSecureDirectoryStream")||
                name.getNameCount()!=1||!expected.isRegularFile()||expected.fileKey()==null)throw unsafe();
            Class<?> dispatcher=Class.forName("sun.nio.fs.UnixNativeDispatcher");
            Method open=dispatcher.getDeclaredMethod("openat",int.class,byte[].class,int.class,int.class);
            close=dispatcher.getDeclaredMethod("close",int.class);
            Method stat=Class.forName("sun.nio.fs.UnixFileAttributes").getDeclaredMethod("get",int.class);
            Field dfd=directory.getClass().getDeclaredField("dfd");
            if(!open.trySetAccessible()||!close.trySetAccessible()||!stat.trySetAccessible()||!dfd.trySetAccessible())throw unsafe();
            faults.at(family+".before-pin");
            // Linux O_PATH | O_NOFOLLOW | O_CLOEXEC. No data open, even if the entry became a FIFO.
            descriptor=(Integer)open.invoke(null,dfd.getInt(directory),name.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),0x200000|0x20000|0x80000,0);
            var pinned=(PosixFileAttributes)stat.invoke(null,descriptor);
            if(!same(expected,pinned))throw unsafe();
            faults.at(family+".after-pin");verify.run();
            if(!same(expected,attributes(directory,name)))throw unsafe();
            faults.at(family+".open-data");
            // This procfs link names our own pinned regular inode, never a user-controlled pathname.
            channel=FileChannel.open(Path.of("/proc/self/fd/"+descriptor),StandardOpenOption.READ);
            if(channel.size()!=expected.size())throw unsafe();
            FileChannel result=channel;channel=null;return result;
        }catch(ReflectiveOperationException|IOException|RuntimeException error){throw unsafe();}
        finally{
            if(channel!=null)try{channel.close();}catch(IOException error){/* refusal already in flight */}
            if(descriptor>=0&&close!=null)try{close.invoke(null,descriptor);}catch(ReflectiveOperationException error){throw unsafe();}
        }
    }
    interface RunnableIO {void run()throws IOException;}
    static byte[] input(Path supplied,long bound,S2SAssemblyInspector.Faults faults)throws IOException{
        Path path=supplied.toAbsolutePath();
        try(var parents=new Directories(path.getParent())){
            Path name=path.getFileName();var expected=attributes(parents.directory(),name);
            if(!expected.isRegularFile()||expected.size()>bound)throw unsafe();
            byte[] bytes;
            try(var channel=regular(parents.directory(),name,expected,faults,"input",parents::verify)){
                bytes=new byte[(int)expected.size()];faults.at("input.read");S2SAssemblyReader.read(channel,0,bytes);
                if(channel.size()!=bytes.length)throw unsafe();
            }
            parents.verify();if(!same(expected,attributes(parents.directory(),name)))throw unsafe();return bytes;
        }catch(IOException|RuntimeException error){throw unsafe();}
    }
    private S2SSecureFiles(){}
}
