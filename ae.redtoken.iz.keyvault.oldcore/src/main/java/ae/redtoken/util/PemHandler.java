package ae.redtoken.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class PemHandler {

    public static String toPEMString(PrivateKey key) {
        StringWriter sw = new StringWriter();
        writeKey(sw, key);
        return sw.getBuffer().toString();

    }

    public static String toPEMString(PublicKey publicKey) {
        StringWriter sw = new StringWriter();
        writePublicKey(sw, publicKey);
        return sw.getBuffer().toString();
    }

    public static String toPEMString(X509Certificate cert) {
        StringWriter sw = new StringWriter();
        writeCert(sw, cert);
        return sw.getBuffer().toString();
    }


    public static String toPEMString(PKCS10CertificationRequest req) {
        StringWriter sw = new StringWriter();
        writeReq(sw, req);
        return sw.getBuffer().toString();
    }


    public static PrivateKey readKey(String path, String fileName) {
        return readKey(new File(path, fileName));
    }

    public static PrivateKey readKey(File file) {
        try {
            return readKey(new FileReader(file));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey readKey(String str) {
        return readKey(new StringReader(str));
    }

    public static PrivateKey readKey(Reader reader) {
        try {
            PrivateKeyInfo info = (PrivateKeyInfo) readPem(reader);
            return new JcaPEMKeyConverter().getPrivateKey(info);
//            return new JcaPEMKeyConverter().getPrivateKey(((PEMKeyPair) pem).getPrivateKeyInfo());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeKey(String path, String fileName, PrivateKey key) {
        writeKey(new File(path, fileName), key);
    }

    public static void writeKey(File file, PrivateKey key) {
        try {
            writeKey(new FileWriter(file), key);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeKey(Writer writer, PrivateKey key) {
        writePem(writer, "PRIVATE KEY", key.getEncoded());
    }

    public static PublicKey readPublicKey(File file) {
        try {
            return readPublicKey(new FileReader(file));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey readPublicKey(String str) {
        return readPublicKey(new StringReader(str));
    }

    public static PublicKey readPublicKey(Reader reader) {
        try {
            SubjectPublicKeyInfo info = (SubjectPublicKeyInfo) readPem(reader);
            return new JcaPEMKeyConverter().getPublicKey(info);
//            return new JcaPEMKeyConverter().getPrivateKey(((PEMKeyPair) pem).getPrivateKeyInfo());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void writePublicKey(String path, String fileName, PublicKey key) {
        writePublicKey(new File(path, fileName), key);
    }

    public static void writePublicKey(File file, PublicKey key) {
        try {
            writePublicKey(new FileWriter(file), key);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writePublicKey(Writer writer, PublicKey key) {
        writePem(writer, "PUBLIC KEY", key.getEncoded());
    }

    public static X509Certificate readCert(String path, String fileName) {
        return readCert(new File(path, fileName));
    }

    public static X509Certificate readCert(File file) {
        try {
            return readCert(new FileReader(file));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate readCert(String str) {
        return readCert(new StringReader(str));
    }

    public static X509Certificate readCert(Reader reader) {

        try {
            JcaX509CertificateConverter jcc = new JcaX509CertificateConverter();
            return jcc.getCertificate((X509CertificateHolder) readPem(reader));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static Collection<X509Certificate> readAllCerts(String path, String fileName) {
        return readAllCerts((new File(path, fileName)));
    }

    public static Collection<X509Certificate> readAllCerts(File file) {
        try {
            return readAllCerts(new FileReader(file));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Collection<X509Certificate> readAllCerts(String str) {
        return readAllCerts(new StringReader(str));
    }

    public static Collection<X509Certificate> readAllCerts(Reader reader) {
        Collection<X509Certificate> certs = new ArrayList<>();
        try {
            while (true) {
                certs.add(readCert(reader));
            }
        } catch (NoObjectReadException ignored) {
        }

        return certs;
    }

    public static void writeCert(String path, String fileName, X509Certificate cert) {
        writeCert(new File(path, fileName), cert);
    }

    public static void writeCert(File file, X509Certificate cert) {
        try {
            writeCert(new FileWriter(file), cert);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeCert(Writer writer, X509Certificate cert) {
        try {
            writePem(writer, "CERTIFICATE", cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeAllCerts(String path, String fileName, Collection<X509Certificate> certs) {
        writeAllCerts(new File(path, fileName), certs);
    }

    public static void writeAllCerts(File file, Collection<X509Certificate> certs) {
        try {
            writeAllCerts(new FileWriter(file), certs);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeAllCerts(Writer writer, Collection<X509Certificate> certs) {
        for (X509Certificate cert : certs)
            writeCert(writer, cert);
    }


    public static String write(X509Certificate cert) {
        StringWriter sw = new StringWriter();
        writeCert(sw, cert);
        return sw.toString();
    }


    /// REQ
    public static PKCS10CertificationRequest readReq(File f) {
        try {
            return readReq(new FileReader(f));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static PKCS10CertificationRequest readReq(String str) {
        return readReq(new StringReader(str));
    }

    public static PKCS10CertificationRequest readReq(Reader reader) {
        try {

            PEMParser pemParser = new PEMParser(reader);
            return (PKCS10CertificationRequest) pemParser.readObject();

        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    public static void writeReq(File file, PKCS10CertificationRequest rq) {
        try {
            writeReq(new FileWriter(file), rq);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeReq(Writer writer, PKCS10CertificationRequest rq) {

        try {
            writePem(writer, "CERTIFICATE REQUEST", rq.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writePem(Writer writer, String type, byte[] data) {
        try {

            PemObject po = new PemObject(type, data);

            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(po);
            pemWriter.flush();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static class NoObjectReadException extends RuntimeException {
    }

    private static Object readPem(Reader reader) {

        try {

            PEMParser pp = new PEMParser(reader);
            Object po = pp.readObject();

            if (po == null)
                throw new NoObjectReadException();

            return po;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}