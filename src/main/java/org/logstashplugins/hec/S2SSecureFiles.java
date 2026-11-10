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
    /** Only kernel-owned descriptor paths are used for operations absent from SecureDirectoryStream. */
    private static Path descriptor(SecureDirectoryStream<Path> directory)throws IOException{
        try{
            if(!System.getProperty("os.name").equals("Linux")||!directory.getClass().getName().equals("sun.nio.fs.UnixSecureDirectoryStream"))throw unsafe();
            Field field=directory.getClass().getDeclaredField("dfd");if(!field.trySetAccessible())throw unsafe();
            return Path.of("/proc/self/fd/"+field.getInt(directory));
        }catch(ReflectiveOperationException error){throw unsafe();}
    }
    static void privateDirectory(SecureDirectoryStream<Path> directory)throws IOException{
        var attrs=directory.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
        if(attrs.fileKey()==null||!attrs.permissions().equals(PosixFilePermissions.fromString("rwx------")))throw unsafe();
        descriptor(directory); // Refuse unsupported hosts before any output is claimed.
    }
    static void sync(SecureDirectoryStream<Path> directory)throws IOException{
        try(var channel=FileChannel.open(descriptor(directory),StandardOpenOption.READ)){channel.force(true);}
    }
    /** CREATE_NEW is the claim: two operators can never own the same destination. */
    static void writeNew(Directories parent,Path name,byte[] bytes,S2SAssemblyInspector.Faults faults,String boundary)throws IOException{
        privateDirectory(parent.directory());parent.verify();
        if(name.getNameCount()!=1||name.isAbsolute()||name.toString().equals(".")||name.toString().equals(".."))throw unsafe();
        Object key=null;int fd=-1;Method close=null;
        try{
            faults.at(boundary+".create");
            Class<?> dispatcher=Class.forName("sun.nio.fs.UnixNativeDispatcher");
            Method open=dispatcher.getDeclaredMethod("openat",int.class,byte[].class,int.class,int.class);close=dispatcher.getDeclaredMethod("close",int.class);
            Method stat=Class.forName("sun.nio.fs.UnixFileAttributes").getDeclaredMethod("get",int.class);
            Field dfd=parent.directory().getClass().getDeclaredField("dfd");
            if(!open.trySetAccessible()||!close.trySetAccessible()||!stat.trySetAccessible()||!dfd.trySetAccessible())throw unsafe();
            // O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC. Pin our own creation, not a later named replacement.
            fd=(Integer)open.invoke(null,dfd.getInt(parent.directory()),name.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),1|0x40|0x80|0x20000|0x80000,0600);
            var created=(PosixFileAttributes)stat.invoke(null,fd);key=created.fileKey();if(key==null||!created.isRegularFile())throw unsafe();
            faults.at(boundary+".after-create");
            try(var channel=FileChannel.open(Path.of("/proc/self/fd/"+fd),StandardOpenOption.WRITE)){
                var buffer=java.nio.ByteBuffer.wrap(bytes);
                while(buffer.hasRemaining()){
                    faults.at(boundary+".write");int limit=buffer.limit();buffer.limit(Math.min(limit,buffer.position()+8192));
                    if(channel.write(buffer)<=0)throw unsafe();buffer.limit(limit);
                }
                faults.at(boundary+".sync");channel.force(true);
                parent.verify();var attrs=attributes(parent.directory(),name);
                if(!key.equals(attrs.fileKey())||!attrs.isRegularFile()||attrs.size()!=bytes.length||!attrs.permissions().equals(PosixFilePermissions.fromString("rw-------")))throw unsafe();
            }
            faults.at(boundary+".directory-sync");sync(parent.directory());parent.verify();
        }catch(ReflectiveOperationException error){throw unsafe();}
        catch(IOException|RuntimeException error){
            // Never remove an existing destination or a replacement belonging to somebody else.
            if(key!=null){
                var attrs=attributes(parent.directory(),name);
                if(key.equals(attrs.fileKey())){faults.at(boundary+".cleanup");parent.directory().deleteFile(name);sync(parent.directory());}
            }
            throw error;
        }finally{
            if(fd>=0&&close!=null)try{close.invoke(null,fd);}catch(ReflectiveOperationException error){throw unsafe();}
        }
    }
    static final class Destination implements AutoCloseable {
        final Directories parent,directory;
        final Path name,claim;final Object key,claimKey;
        Destination(Path supplied,S2SAssemblyInspector.Faults faults)throws IOException{
            Path path=supplied.toAbsolutePath();name=path.getFileName();
            if(name==null||name.toString().equals(".")||name.toString().equals(".."))throw unsafe();
            claim=Path.of(".recovery-claim-"+TokenStore.fingerprint(name.toString()));
            parent=new Directories(path.getParent());Directories opened=null;
            Object ownedClaim=null;
            try{
                privateDirectory(parent.directory());parent.verify();
                Path pinned=descriptor(parent.directory());
                if(Files.exists(pinned.resolve(name),LinkOption.NOFOLLOW_LINKS))throw unsafe();
                writeNew(parent,claim,new byte[0],faults,"destination.claim");ownedClaim=attributes(parent.directory(),claim).fileKey();claimKey=ownedClaim;
                Path staging=Path.of(".recovery-stage-"+UUID.randomUUID());faults.at("destination.create");
                Files.createDirectory(pinned.resolve(staging),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                faults.at("destination.mkdir");
                opened=new Directories(path.getParent().resolve(staging));privateDirectory(opened.directory());
                key=opened.directory().getFileAttributeView(PosixFileAttributeView.class).readAttributes().fileKey();
                writeNew(opened,Path.of("recovery-incomplete"),new byte[]{1},faults,"destination.recovery-incomplete");
                sync(opened.directory());sync(parent.directory());opened.verify();opened.close();opened=null;
                parent.verify();faults.at("destination.expose");
                // The exclusive sibling claim serializes builders. Default move refuses every existing
                // final entry (including empty directories); never request replacement or adoption.
                Files.move(pinned.resolve(staging),pinned.resolve(name));faults.at("destination.exposed");
                opened=new Directories(path);directory=opened;verify();sync(parent.directory());
            }catch(IOException|RuntimeException error){
                try{if(opened!=null)opened.close();}finally{
                    try{if(ownedClaim!=null&&ownedClaim.equals(attributes(parent.directory(),claim).fileKey())){parent.directory().deleteFile(claim);sync(parent.directory());}}
                    finally{parent.close();}
                }
                throw error;
            }
        }
        void verify()throws IOException{
            parent.verify();directory.verify();privateDirectory(directory.directory());
            if(!Objects.equals(key,attributes(parent.directory(),name).fileKey()))throw unsafe();
        }
        void write(String name,byte[] bytes,S2SAssemblyInspector.Faults faults)throws IOException{
            verify();writeNew(directory,Path.of(name),bytes,faults,"destination."+name);verify();
        }
        void finish(S2SAssemblyInspector.Faults faults)throws IOException{
            verify();faults.at("destination.finish");directory.directory().deleteFile(Path.of("recovery-incomplete"));
            try{faults.at("destination.finish-sync");sync(directory.directory());sync(parent.directory());verify();}
            catch(IOException error){
                // If storage also refuses guard restoration, a fully published outcome is ambiguous.
                try{writeNew(directory,Path.of("recovery-incomplete"),new byte[]{1},faults,"destination.invalidate");}
                catch(IOException restore){error.addSuppressed(restore);}
                throw error;
            }
        }
        @Override public void close()throws IOException{
            try{directory.close();}
            finally{try{parent.verify();if(!claimKey.equals(attributes(parent.directory(),claim).fileKey()))throw unsafe();parent.directory().deleteFile(claim);sync(parent.directory());}finally{parent.close();}}
        }
    }
    private S2SSecureFiles(){}
}
