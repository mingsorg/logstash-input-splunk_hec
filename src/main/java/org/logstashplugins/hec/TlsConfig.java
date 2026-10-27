package org.logstashplugins.hec;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;

public final class TlsConfig {
    public record Options(boolean enabled, Path identityDirectory, String sans, Path keystore,
                          String storeType, String password, Path certificate, Path key,
                          Path clientCA, boolean requireClientCertificate) {}
    private final SSLContext context;
    private final boolean clientAuth;
    public TlsConfig(Options o) throws Exception {
        clientAuth=o.requireClientCertificate;
        if(!o.enabled) {
            if(o.keystore!=null||o.certificate!=null||o.key!=null||o.clientCA!=null||clientAuth)
                throw new IllegalArgumentException("TLS material requires TLS enabled");
            context=null;return;
        }
        if(o.keystore!=null && (o.certificate!=null||o.key!=null)) throw new IllegalArgumentException("choose keystore or PEM");
        KeyStore identity;
        char[] pass=o.password.toCharArray();
        if(o.keystore!=null) {
            identity=KeyStore.getInstance(o.storeType);
            try(InputStream in=Files.newInputStream(o.keystore)){identity.load(in,pass);}
        } else if(o.certificate!=null||o.key!=null) {
            if(o.certificate==null||o.key==null)throw new IllegalArgumentException("both PEM certificate and PKCS8 key required");
            identity=KeyStore.getInstance("PKCS12");identity.load(null,pass);
            byte[] der=pem(Files.readString(o.key),"PRIVATE KEY");PrivateKey key=null;
            for(String algorithm:List.of("RSA","EC","Ed25519"))try{key=KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));break;}catch(GeneralSecurityException ignored){}
            if(key==null)throw new IllegalArgumentException("unsupported PKCS8 private key");
            Collection<? extends java.security.cert.Certificate> chain;
            try(InputStream in=Files.newInputStream(o.certificate)){chain=CertificateFactory.getInstance("X.509").generateCertificates(in);}
            if(chain.isEmpty())throw new IllegalArgumentException("empty certificate chain");
            identity.setKeyEntry("server",key,pass,chain.toArray(java.security.cert.Certificate[]::new));
        } else {
            ensureSelfSigned(o.identityDirectory,o.sans);
            pass=Files.readString(o.identityDirectory.resolve("password"),StandardCharsets.UTF_8).strip().toCharArray();
            identity=KeyStore.getInstance("PKCS12");
            try(InputStream in=Files.newInputStream(o.identityDirectory.resolve("server.p12"))){identity.load(in,pass);}
        }
        boolean keyFound=false;
        for(Enumeration<String> aliases=identity.aliases();aliases.hasMoreElements();){
            String alias=aliases.nextElement();
            if(identity.isKeyEntry(alias)){
                keyFound=true;
                X509Certificate cert=(X509Certificate)identity.getCertificate(alias);cert.checkValidity();
                if(cert.getSubjectAlternativeNames()==null)throw new IllegalArgumentException("server certificate requires SANs");
                // Verify matching private/public key at startup rather than deferring to a handshake.
                PrivateKey key=(PrivateKey)identity.getKey(alias,pass);
                String alg=key.getAlgorithm().equals("RSA")?"SHA256withRSA":key.getAlgorithm().equals("EC")?"SHA256withECDSA":"Ed25519";
                Signature signature=Signature.getInstance(alg);byte[] challenge=new byte[32];new SecureRandom().nextBytes(challenge);
                signature.initSign(key);signature.update(challenge);byte[] signed=signature.sign();
                signature.initVerify(cert);signature.update(challenge);
                if(!signature.verify(signed))throw new IllegalArgumentException("certificate and key mismatch");
            }
        }
        if(!keyFound)throw new IllegalArgumentException("keystore has no server private key");
        KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(identity,pass);
        TrustManager[] trust=null;
        if(o.clientCA!=null){
            KeyStore ca=KeyStore.getInstance("PKCS12");ca.load(null,new char[0]);
            try(InputStream in=Files.newInputStream(o.clientCA)){
                int n=0;for(var cert:CertificateFactory.getInstance("X.509").generateCertificates(in))ca.setCertificateEntry("ca"+(n++),cert);
                if(n==0)throw new IllegalArgumentException("empty client CA file");
            }
            TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(ca);trust=tm.getTrustManagers();
        }else if(clientAuth)throw new IllegalArgumentException("mTLS requires an explicit client CA");
        context=SSLContext.getInstance("TLS");context.init(km.getKeyManagers(),trust,new SecureRandom());
    }
    ServerSocket bind(String host,int port,int backlog)throws IOException{
        ServerSocket socket=context==null?new ServerSocket():context.getServerSocketFactory().createServerSocket();
        if(socket instanceof SSLServerSocket ssl){ssl.setEnabledProtocols(new String[]{"TLSv1.3","TLSv1.2"});ssl.setNeedClientAuth(clientAuth);}
        socket.setReuseAddress(true);socket.bind(new InetSocketAddress(host,port),backlog);return socket;
    }
    private static byte[] pem(String text,String kind){
        String begin="-----BEGIN "+kind+"-----",end="-----END "+kind+"-----";
        if(!text.contains(begin)||!text.contains(end))throw new IllegalArgumentException("PKCS8 PEM key required");
        return Base64.getMimeDecoder().decode(text.substring(text.indexOf(begin)+begin.length(),text.indexOf(end)));
    }
    private static synchronized void ensureSelfSigned(Path dir,String sans)throws Exception{
        if(Files.exists(dir,LinkOption.NOFOLLOW_LINKS)){
            if(!Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS)||!Files.isReadable(dir.resolve("server.p12"))||!Files.isReadable(dir.resolve("password")))
                throw new IOException("existing TLS identity unreadable; refusing regeneration");
            return;
        }
        Path parent=dir.toAbsolutePath().getParent();Files.createDirectories(parent);
        Path temp=Files.createTempDirectory(parent,".hec-tls-");restrict(temp,true);
        try{
            String password=UUID.randomUUID().toString();Path pw=temp.resolve("password");
            Files.writeString(pw,password,StandardOpenOption.CREATE_NEW);restrict(pw,false);
            List<String> command=new ArrayList<>(List.of(Path.of(System.getProperty("java.home"),"bin","keytool").toString(),
                "-genkeypair","-alias","server","-keyalg","RSA","-keysize","3072","-validity","3650",
                "-dname","CN=Logstash HEC","-ext","SAN="+sans,"-ext","EKU=serverAuth",
                "-storetype","PKCS12","-keystore",temp.resolve("server.p12").toString(),"-storepass:file",pw.toString(),"-noprompt"));
            Process process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            if(!process.waitFor(30,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor();throw new IOException("keytool timed out");}
            if(process.exitValue()!=0)throw new IOException("keytool rejected certificate identity configuration");
            restrict(temp.resolve("server.p12"),false);
            KeyStore store=KeyStore.getInstance("PKCS12");
            try(InputStream in=Files.newInputStream(temp.resolve("server.p12"))){store.load(in,password.toCharArray());}
            String cert="-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(store.getCertificate("server").getEncoded())+"\n-----END CERTIFICATE-----\n";
            Files.writeString(temp.resolve("server.crt"),cert);restrict(temp.resolve("server.crt"),false);
            Files.move(temp,dir,StandardCopyOption.ATOMIC_MOVE);
        }finally{
            if(Files.exists(temp)){try(var paths=Files.walk(temp)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
        }
    }
    private static void restrict(Path path,boolean directory)throws IOException{
        if(Files.getFileStore(path).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(path,PosixFilePermissions.fromString(directory?"rwx------":"rw-------"));
    }
}
