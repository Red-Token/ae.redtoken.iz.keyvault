package ae.redtoken.iz.protocolls.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;


import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class TestSSH {

    public static void writeUint32(ByteArrayOutputStream out, long value) throws IOException {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Value out of range for uint32: " + value);
        }

        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    /***
     * This test tests the ssh agent by loading a key from the file system,
     *
     * things that need to be set is
     *
     *   SSH_AUTH_SOCK=/tmp/zool.sock; export SSH_AUTH_SOCK;
     *
     *   Make sure that the following is added to the authorized keys
     * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJ rene.malmgren@redtoken.ae
     *
     *
     *
     *
     */

    @SneakyThrows
    @Test
    void testSshAgent() {
        Security.addProvider(new BouncyCastleProvider());
        SshAgent agent = new SshAgent();

        System.out.println("Waiting for connection...");
        UnixSocketChannel inChannel = agent.server.accept();

        SshAgentConnection sshAgentConnection = new SshAgentConnection(inChannel);

//        String outSocketName = "/tmp/ssh-DsXwb1Irog5J/agent.3065356";
//        File outSocketFile = new File(outSocketName);
//        UnixSocketAddress outAddress = new UnixSocketAddress(outSocketFile);
//        UnixSocketChannel outChannel = UnixSocketChannel.open(outAddress);

//        SshTokenWriter requestWriter = new SshTokenWriter(outChannel);
//        SshTokeReader responseReader = new SshTokeReader(outChannel);

//        sshAgentConnection.requestWriter = requestWriter;
//        sshAgentConnection.responseReader = responseReader;

        for (int i = 0; i < 100; i++) {

            sshAgentConnection.processNextToken();


//            SshTokeReader.AbstractSshToken requestToken = requestReader.readSshToken();
//
//            if (requestToken instanceof SshTokeReader.SshAgentCSignRequest) {
//                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
//
//                SshTokeReader.SshAgentCSignRequest sacsr = (SshTokeReader.SshAgentCSignRequest) requestToken;
//
//                EdDSAPublicKey pk = (EdDSAPublicKey) sacsr.key;
//                Ed25519PublicKeyParameters bcParams = new Ed25519PublicKeyParameters(pk.getAbyte(), 0);
//                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcParams);
//
//                // This is the key we need to use the one above does not work atleast not with the Key that we load from file
//                PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
//
//                byte[] encoded = publicKey.getEncoded();
//                System.out.println(encoded.length);
//                System.out.println(new String(encoded));
//
//                // Data to be signed.
//                byte[] data = sacsr.data;
//                SshTokeReader.AbstractSshToken responseToken;
//
//                {
//                    // Private key
//                    String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
//                    AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));
//
//                    // This is BC doing the magic
//                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
//                    PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
//
//                    publicKey.getEncoded();
//
//                    SshKeyType keyType = SshKeyType.fromBcName(privateKey.getAlgorithm());
//
//                    Signature signature = SecurityUtils.getSignature(keyType.bcName);
//                    signature.initSign(privateKey);
//                    signature.update(data);
//                    byte[] sign = signature.sign();
//
//                    responseToken = new SshTokeReader.SshAgentSignResponse(new SshTokeReader.SshAgentSignResponse.SshSignature(keyType.sshName, sign));
//                }
//
//                System.out.printf("SshToken: %s\n", responseToken);
//                responseWriter.writeSshToken(responseToken);
//
//
//            } else if (requestToken instanceof SshTokeReader.SshAgentCExetion) {
//
//                requestWriter.writeSshToken(requestToken);
//                SshTokeReader.AbstractSshToken responseToken = responseReader.readSshToken();
//                responseWriter.writeSshToken(responseToken);
//
//            } else if (requestToken instanceof SshTokeReader.SshAgentCRequestIdentities) {
//
//                requestWriter.writeSshToken(requestToken);
//                SshTokeReader.AbstractSshToken responseToken = responseReader.readSshToken();
//                responseWriter.writeSshToken(responseToken);
//
//            } else {
//
//            }

            System.out.println("Next round");
        }
    }

//    @SneakyThrows
//    @Test
//    void testSshAgentOld() {
////        String sockName = "/tmp/ssh-Jo5obhsWd3xP/agent.479552";
////        String outSocketName = "/run/user/1000/keyring/ssh";
//
////        String inSocketName = "/tmp/mysocket.sock";
////        File inSocketFile = new File(inSocketName);
//
////        inSocketFile.delete(); // make sure old socket is removed
////        UnixServerSocketChannel server = UnixServerSocketChannel.open();
////        server.configureBlocking(true);
////        server.socket().bind(new UnixSocketAddress(inSocketFile));
////
////        System.out.println("Waiting for connection...");
////        UnixSocketChannel inChannel = server.accept();
//
////        UnixSocketChannel outChannel = UnixSocketChannel.open(address);
//
////        Thread t = new Thread(new Runnable() {
////            @SneakyThrows
////            @Override
////            public void run() {
////                // Connect to the server socket
////                SshTokeReader sshTokeReader = new SshTokeReader(inChannel);
////                SshTokenWriter sshTokenWriter = new SshTokenWriter(outChannel);
////
////                boolean running = true;
////                while (running) {
////                    byte[] bytes = sshTokeReader.readToken();
////
////                    System.out.println("Read " + bytes.length + " bytes");
////
////                    sshTokenWriter.writeToken(bytes);
////
////                    System.out.println("Writing " + bytes.length + " bytes");
////                }
////            }
////        });
////
////        Thread t2 = new Thread(new Runnable() {
////            @SneakyThrows
////            @Override
////            public void run() {
////                // Connect to the server socket
////                SshTokeReader sshTokeReader = new SshTokeReader(outChannel);
////                SshTokenWriter sshTokenWriter = new SshTokenWriter(inChannel);
////
////                boolean running = true;
////                while (running) {
////                    byte[] bytes = sshTokeReader.readToken();
////
////                    System.out.println("Read2 " + bytes.length + " bytes");
////
////                    sshTokenWriter.writeToken(bytes);
////
////                    System.out.println("Writing2 " + bytes.length + " bytes");
////                }
////            }
////        });
////
////        t2.start();
////        t.start();
////
////        t.join();
////
////
//        // Let there be light at the end of the tunnel
//
//        // step 1, open a socket
//
//
//        String inSocketName = "/tmp/zool.sock";
//        File inSocketFile = new File(inSocketName);
//        inSocketFile.delete(); // make sure old socket is removed
//
//        UnixSocketAddress inAddress = new UnixSocketAddress(inSocketFile);
//        UnixServerSocketChannel server = UnixServerSocketChannel.open();
//        server.configureBlocking(true);
//        server.socket().bind(inAddress);
//
//        System.out.println("Waiting for connection...");
//        UnixSocketChannel inChannel = server.accept();
//
//        SshTokeReader requestReader = new SshTokeReader(inChannel);
//        SshTokenWriter responseWriter = new SshTokenWriter(inChannel);
//
//        String outSocketName = "/tmp/ssh-DsXwb1Irog5J/agent.3065356";
//        File outSocketFile = new File(outSocketName);
//        UnixSocketAddress outAddress = new UnixSocketAddress(outSocketFile);
//        UnixSocketChannel outChannel = UnixSocketChannel.open(outAddress);
//
//        SshTokenWriter requestWriter = new SshTokenWriter(outChannel);
//        SshTokeReader responseReader = new SshTokeReader(outChannel);
//
//        for (int i = 0; i < 100; i++) {
//            SshTokeReader.AbstractSshToken requestToken = requestReader.readSshToken();
//            requestWriter.writeSshToken(requestToken);
//
//            SshTokeReader.AbstractSshToken responseToken = responseReader.readSshToken();
//
//            if (i == 2) {
//                SshTokeReader.SshAgentCSignRequest sacssr = (SshTokeReader.SshAgentCSignRequest) requestToken;
//                SshTokeReader.SshAgentSignResponse sasr = (SshTokeReader.SshAgentSignResponse) responseToken;
//
//                EdDSAPublicKey pk = (EdDSAPublicKey) sacssr.key;
//                Ed25519PublicKeyParameters bcParams = new Ed25519PublicKeyParameters(pk.getAbyte(), 0);
//                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcParams);
//
//                // This is the key we need to use the one above does not work atleast not with the Key that we load from file
//                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
//                PublicKey key = converter.getPublicKey(subjectPublicKeyInfo);
//
//                byte[] data = sacssr.data;
//                byte[] signature = sasr.signature;
//
//                System.out.println(new String(signature));
//
//                System.out.println(key.getClass());
//
//                ByteBuffer buffer = ByteBuffer.wrap(signature);
//                byte[] type = SshTokeReader.AbstractSshToken.readByteArray(buffer);
//                byte[] sigData = SshTokeReader.AbstractSshToken.readByteArray(buffer);
//
//                {
//                    Signature verifier = SecurityUtils.getSignature("Ed25519");
//                    verifier.initVerify(key);
//                    verifier.update(data);
//                    boolean verify = verifier.verify(sigData);
//                    System.out.println(verify);
//                    Assertions.assertTrue(verify);
//                }
//                // Let's do this again :)
//
//                String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
//                AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));
//
//                // This is BC doing the magic
//                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
//                PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
//
//                Signature signature2 = SecurityUtils.getSignature("Ed25519");

    /// /        signature.initSign(keyPair.getPrivate());
//                signature2.initSign(privateKey);
//                signature2.update(data);
//
//                byte[] sign = signature2.sign();
//
//                {
//                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                    DataOutputStream dos = new DataOutputStream(baos);
//                    SshTokeReader.AbstractSshToken.writeByteArray(dos, type);
//                    SshTokeReader.AbstractSshToken.writeByteArray(dos, sign);
//
//                    SshTokeReader.SshAgentSignResponse sasr1;
//                    sasr1 = new SshTokeReader.SshAgentSignResponse(baos.toByteArray());
//
//                    responseToken = sasr1;
//
//                    ByteBuffer bbs = ByteBuffer.wrap(sasr1.signature);
//
//                    String type2 = SshTokeReader.AbstractSshToken.readString(bbs);
//                    byte[] sigData2 = SshTokeReader.AbstractSshToken.readByteArray(bbs);
//
//                    System.out.println(type2);
//
//                    Signature verifier = SecurityUtils.getSignature("Ed25519");
//                    verifier.initVerify(key);
//                    verifier.update(data);
//                    boolean verify = verifier.verify(sigData2);
//                    System.out.println(verify);
//
//                    Assertions.assertTrue(verify);
//                }
//
//                System.out.printf("SshToken: %s\n", responseToken);
//
//            }
//
//            responseWriter.writeSshToken(responseToken);
//
//            System.out.println("Next round");
//        }
//    }


    static class TestSshTokeReader extends SshTokeReader {
        final private String dataString;

        TestSshTokeReader(String dataString) {
            super(null);
            this.dataString = dataString;
        }

        @Override
        byte[] readTokenBytes() {
            return Base64.getDecoder().decode(dataString);
        }
    }

    static class TestSshTokenWriter extends SshTokenWriter {

        final private String dataString;

        TestSshTokenWriter(String dataString) {
            super(null);
            this.dataString = dataString;
        }

        @Override
        public void writeTokenBytes(byte[] bytes) {
            String string = Base64.getEncoder().encodeToString(bytes);

            Assertions.assertEquals(dataString, string);
            System.out.println(string);
        }
    }

    @SneakyThrows
    @Test
    void testExtention() {

        //R:85:DAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAFS9ob21lL3JlbmUvaWRfZWQyNTUxOQ==
        String dataString = "GwAAABhzZXNzaW9uLWJpbmRAb3BlbnNzaC5jb20AAAAzAAAAC3NzaC1lZDI1NTE5AAAAICR5uvD99hAty9yXmdsUVDPFi9Fe1ZmV12TmaYN3TXi/AAAAQCQzrNnzkKys48QqekjRSaK6XJ47PrkvNiGG7IKrVORspw9zHkPaVgRl4xiX7Uc6pOpCWBLaUyiIAXfXceORSWkAAABTAAAAC3NzaC1lZDI1NTE5AAAAQJ9G09dPofk+Nu9CcQpqJA1Bjc7PPCPnFOaLFNYC0OsTRzB017CwpRnLDMdx9dzE39KNtT6+70y/Zso/31D6hAQA";

        SshTokeReader testReader = new TestSshTokeReader(dataString);
        SshTokeReader.AbstractSshToken abstractSshToken = testReader.readSshToken();

        SshTokenWriter testWriter = new TestSshTokenWriter(dataString);
        testWriter.writeSshToken(abstractSshToken);
    }

    @SneakyThrows
    @Test
    void testId() {

        //R:324:DQAAADMAAAALc3NoLWVkMjU1MTkAAAAgawt+oXk5PhlnQK0eOkMM+XYamX9WgTOZw9DEHjarnMkAAAEEAAAAQMe7WU5IXcCqHT3x6kOVdxwr/pOowFyYHllTJBupc9gRhneIGygsVXk8okqd5H7juiXZ6Qc4f0JYS8y4iaDPBfwyAAAABHJlbmUAAAAOc3NoLWNvbm5lY3Rpb24AAAAjcHVibGlja2V5LWhvc3Rib3VuZC12MDBAb3BlbnNzaC5jb20BAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJHm68P32EC3L3JeZ2xRUM8WL0V7VmZXXZOZpg3dNeL8AAAAA
        String dataString = "DAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAFS9ob21lL3JlbmUvaWRfZWQyNTUxOQ==";

        SshTokeReader testReader = new TestSshTokeReader(dataString);
        SshTokeReader.AbstractSshToken abstractSshToken = testReader.readSshToken();

        SshTokenWriter testWriter = new TestSshTokenWriter(dataString);
        testWriter.writeSshToken(abstractSshToken);
    }

    @SneakyThrows
    @Test
    void testSigReq() {
        //DgAAAFMAAAALc3NoLWVkMjU1MTkAAABA5OiiuavjwFcbcIHKuFk9b95+xWboWE5Zl8rkrYRenVQuARi7dc0BkCJwouSnI20c+IiCxQjPEHB73O3cD0+yAQ==
        String dataString = "DQAAADMAAAALc3NoLWVkMjU1MTkAAAAgawt+oXk5PhlnQK0eOkMM+XYamX9WgTOZw9DEHjarnMkAAAEEAAAAQMe7WU5IXcCqHT3x6kOVdxwr/pOowFyYHllTJBupc9gRhneIGygsVXk8okqd5H7juiXZ6Qc4f0JYS8y4iaDPBfwyAAAABHJlbmUAAAAOc3NoLWNvbm5lY3Rpb24AAAAjcHVibGlja2V5LWhvc3Rib3VuZC12MDBAb3BlbnNzaC5jb20BAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJHm68P32EC3L3JeZ2xRUM8WL0V7VmZXXZOZpg3dNeL8AAAAA";

        SshTokeReader testReader = new TestSshTokeReader(dataString);
        SshTokeReader.AbstractSshToken abstractSshToken = testReader.readSshToken();

        SshTokenWriter testWriter = new TestSshTokenWriter(dataString);
        testWriter.writeSshToken(abstractSshToken);
    }

    @SneakyThrows
    @Test
    void testSigResp() {
        //DgAAAFMAAAALc3NoLWVkMjU1MTkAAABA5OiiuavjwFcbcIHKuFk9b95+xWboWE5Zl8rkrYRenVQuARi7dc0BkCJwouSnI20c+IiCxQjPEHB73O3cD0+yAQ==
        String dataString = "DgAAAFMAAAALc3NoLWVkMjU1MTkAAABA5OiiuavjwFcbcIHKuFk9b95+xWboWE5Zl8rkrYRenVQuARi7dc0BkCJwouSnI20c+IiCxQjPEHB73O3cD0+yAQ==";

        SshTokeReader testReader = new TestSshTokeReader(dataString);
        SshTokeReader.AbstractSshToken abstractSshToken = testReader.readSshToken();

        SshTokenWriter testWriter = new TestSshTokenWriter(dataString);
        testWriter.writeSshToken(abstractSshToken);
    }

    @SneakyThrows
    @Test
    void testAgentDidy() {
        //DQAAADMAAAALc3NoLWVkMjU1MTkAAAAgawt+oXk5PhlnQK0eOkMM+XYamX9WgTOZw9DEHjarnMkAAAEEAAAAQI9n/PWE1cRhyELM36Vt8JDbtBMAUp7P9x3YD5v1ZUaVt26oCCBRluHNJQLwVBVs3YCFj7fe6SXkvQxAQQ4eHAgyAAAABHJlbmUAAAAOc3NoLWNvbm5lY3Rpb24AAAAjcHVibGlja2V5LWhvc3Rib3VuZC12MDBAb3BlbnNzaC5jb20BAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJHm68P32EC3L3JeZ2xRUM8WL0V7VmZXXZOZpg3dNeL8AAAAA
        //DgAAAFMAAAALc3NoLWVkMjU1MTkAAABAxE5Gepmzn7QyCSgPgd0AdmnIdLCyRB0b+yMR+X4kFfnUuSQkUF9j1wq2boMZ2EicbEB+sApAgqwnvPASUf7YDg==

        String reqData = "DQAAADMAAAALc3NoLWVkMjU1MTkAAAAgawt+oXk5PhlnQK0eOkMM+XYamX9WgTOZw9DEHjarnMkAAAEEAAAAQI9n/PWE1cRhyELM36Vt8JDbtBMAUp7P9x3YD5v1ZUaVt26oCCBRluHNJQLwVBVs3YCFj7fe6SXkvQxAQQ4eHAgyAAAABHJlbmUAAAAOc3NoLWNvbm5lY3Rpb24AAAAjcHVibGlja2V5LWhvc3Rib3VuZC12MDBAb3BlbnNzaC5jb20BAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJHm68P32EC3L3JeZ2xRUM8WL0V7VmZXXZOZpg3dNeL8AAAAA";

        SshTokeReader testReader = new TestSshTokeReader(reqData);
        SshTokeReader.SshAgentCSignRequest signRequest = (SshTokeReader.SshAgentCSignRequest) testReader.readSshToken();

        PublicKey key = signRequest.key;

        System.out.println(key);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
        AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));

        Ed25519PrivateKeyParameters pkp = (Ed25519PrivateKeyParameters) privateKeyParams;

        Ed25519PublicKeyParameters ed25519PublicKeyParameters = pkp.generatePublicKey();

//        byte[] encoded = ed25519PublicKeyParameters.getEncoded();
//
//        // Convert to PublicKey object
//        Ed25519KeyGenerationParameters
//
//        EdDSAKeyFactory keyFactory = new EdDSAKeyFactory();
//        PublicKey publicKey = keyFactory.engineGeneratePublic(
//                new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519", publicKeyParams.getEncoded())
//        );
//
//        String base64Pub = "AAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJ";
//        byte[] pubKeyBytes = Base64.getDecoder().decode(base64Pub);
//
//        EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName("Ed25519");
//
//        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(pubKeyBytes, params);
//
//        EdDSAPublicKey publicKey = new EdDSAPublicKey(pubKeySpec);


        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey jKey = converter.getPrivateKey(privateKeyInfo);

        System.out.println(jKey);

        //6b0b7ea179393e196740ad1e3a430cf9761a997f56813399c3d0c41e36ab9cc9
        //6b0b7ea179393e196740ad1e3a430cf9761a997f56813399c3d0c41e36ab9cc9


        String respData = "DgAAAFMAAAALc3NoLWVkMjU1MTkAAABAxE5Gepmzn7QyCSgPgd0AdmnIdLCyRB0b+yMR+X4kFfnUuSQkUF9j1wq2boMZ2EicbEB+sApAgqwnvPASUf7YDg==";

        SshTokeReader testReader2 = new TestSshTokeReader(respData);
        SshTokeReader.SshAgentSignResponse signResponse = (SshTokeReader.SshAgentSignResponse) testReader2.readSshToken();

        ByteArrayBuffer bab = new ByteArrayBuffer();

        Signature signature = SecurityUtils.getSignature(jKey.getAlgorithm());
        signature.initSign(jKey);
        signature.update(signRequest.data);
        byte[] sign = signature.sign();

        System.out.println(Base64.getEncoder().encodeToString(sign));


//        Signature signature2 = SecurityUtils.getSignature(jKey.getAlgorithm());
//        signature2.initVerify(signRequest.key);
//        signature2.verify(sign);

//        Buffer buf = new ByteArrayBuffer();
//        buf.putString("ssh-ed25519");
//        buf.putBytes(rawSig);
//        byte[] signatureBlob = buf.getCompactData();
//
//        Signature signer = SecurityUtils.getSignatureFactory("ssh-ed25519").create();
//        signer.initSigner(keyPair.getPrivate());
//        signer.update(dataToSign);
//        byte[] rawSig = signer.sign();

        System.out.println(new String(signResponse.signature.signature()));
    }

    //    @SneakyThrows
//    @Test
//    void testAgent() {
//
//        Thread t = new Thread(new Runnable() {
//
//            @SneakyThrows
//            @Override
//            public void run() {
//                File socketFile = new File("/tmp/mysocket.sock");
//                socketFile.delete(); // make sure old socket is removed
//
//                UnixServerSocketChannel server = UnixServerSocketChannel.open();
//                try {
//                    server.configureBlocking(true);
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//                server.socket().bind(new UnixSocketAddress(socketFile));
//
//                System.out.println("Waiting for connection...");
//                UnixSocketChannel client = server.accept();
//                ByteBuffer buffer = ByteBuffer.allocate(1024);
//                client.read(buffer);
//
//                System.out.println("Received: " + new String(buffer.array()).trim());
//                client.close();
//                server.close();
//            }
//        });
//
//        t.start();
//
//        Thread.sleep(1000);
//
//        // Let there be light at the end of the tunnel
//        File socketFile = new File("/tmp/mysocket.sock");
//
//        // Connect to the server socket
//        UnixSocketAddress address = new UnixSocketAddress(socketFile);
//        UnixSocketChannel channel = UnixSocketChannel.open(address);
//
//        // Send a message
//        ByteBuffer buffer = ByteBuffer.wrap("Hello server".getBytes());
//        channel.write(buffer);
//        channel.close();


//    }


    @SneakyThrows
    @Test
    void testSalamander() {
        Security.addProvider(new BouncyCastleProvider());

        // Example: from "ssh-ed25519 AAAAC3..." line
        String b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJ";
        byte[] blob = Base64.getDecoder().decode(b64);

        // Read first string ("ssh-ed25519")
        ByteBuffer bb = ByteBuffer.wrap(blob);
        int len1 = bb.getInt();
        byte[] typeBytes = new byte[len1];
        bb.get(typeBytes);
        String type = new String(typeBytes, StandardCharsets.UTF_8);
        if (!"ssh-ed25519".equals(type)) {
            throw new IllegalArgumentException("Not an ssh-ed25519 key");
        }

        // Read second string (32-byte public key)
        int len2 = bb.getInt();
        byte[] pubRaw = new byte[len2];
        bb.get(pubRaw);
        if (len2 != 32) throw new IllegalArgumentException("Wrong key length");

        // Wrap raw key in X.509 SubjectPublicKeyInfo
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                pubRaw
        );

        byte[] spkiEncoded = spki.getEncoded();

        // Build PublicKey object
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(spkiEncoded));

        System.out.println(pubKey);

        // SIG
        String sigData = "xE5Gepmzn7QyCSgPgd0AdmnIdLCyRB0b+yMR+X4kFfnUuSQkUF9j1wq2boMZ2EicbEB+sApAgqwnvPASUf7YDg==";
        byte[] sigDataBytes = Base64.getDecoder().decode(sigData);

        Signature signature2 = SecurityUtils.getSignature(pubKey.getAlgorithm());
        signature2.initVerify(pubKey);
        boolean verify = signature2.verify(sigDataBytes);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
        AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));

        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

        System.out.println(privateKey.getFormat());

        System.out.println(privateKey);

        System.out.println(pubKey);

        System.out.println(verify);

        byte[] bytes = "Hello".getBytes();
        Signature signature = SecurityUtils.getSignature(pubKey.getAlgorithm());
        signature.initSign(privateKey);
        signature.update(bytes);
        byte[] signData = signature.sign();

        System.out.println(new String(signData));

        Signature verifyer = SecurityUtils.getSignature(pubKey.getAlgorithm());
        verifyer.initVerify(pubKey);
        verifyer.update(bytes);
        verifyer.verify(signData);
        System.out.println(verifyer.verify(signData));
    }


    @SneakyThrows
    @Test
    void testZool() {

        KeyPairGenerator keyPairGenerator = SecurityUtils.getKeyPairGenerator("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        System.out.println(keyPair.getPublic());
        System.out.println(keyPair.getPublic().getClass());
        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPrivate().getClass());

        // This loads the private key from file

        String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
        AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));

        // This is BC doing the magic
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

        // Now  the private key is loaded from file (replace with KeyMaster)

        System.out.println(privateKey);
        System.out.println(privateKey.getClass());

        // Example: from "ssh-ed25519 AAAAC3..." line
        String b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJ";
        byte[] blob = Base64.getDecoder().decode(b64);

        ByteArrayBuffer buffer = new ByteArrayBuffer(blob);
        PublicKey rawPublicKeyFromPacket = buffer.getRawPublicKey();

        System.out.println(rawPublicKeyFromPacket);
        System.out.println(rawPublicKeyFromPacket.getClass());

        EdDSAPublicKey pk = (EdDSAPublicKey) rawPublicKeyFromPacket;
        Ed25519PublicKeyParameters bcParams = new Ed25519PublicKeyParameters(pk.getAbyte(), 0);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcParams);

        // This is the key we need to use the one above does not work atleast not with the Key that we load from file
        PublicKey pubKeyConvertedToBC = converter.getPublicKey(subjectPublicKeyInfo);

        System.out.println(pubKeyConvertedToBC);
        System.out.println(pubKeyConvertedToBC.getClass());

//        String format = pk.getFormat();
//        System.out.println(new String(pk.getEncoded()));
//
//        // Read first string ("ssh-ed25519")
//        ByteBuffer bb = ByteBuffer.wrap(blob);
//        int len1 = bb.getInt();
//        byte[] typeBytes = new byte[len1];
//        bb.get(typeBytes);
//        String type = new String(typeBytes, StandardCharsets.UTF_8);
//        if (!"ssh-ed25519".equals(type)) {
//            throw new IllegalArgumentException("Not an ssh-ed25519 key");
//        }
//
//        // Read second string (32-byte public key)
//        int len2 = bb.getInt();
//        byte[] pubRaw = new byte[len2];
//        bb.get(pubRaw);
//        if (len2 != 32) throw new IllegalArgumentException("Wrong key length");
//
//        // Wrap raw key in X.509 SubjectPublicKeyInfo
//        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
//                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
//                pubRaw
//        );
//
//        PublicKey publicKey = converter.getPublicKey(spki);
//
//        System.out.println(publicKey);
//        System.out.println(publicKey.getClass());


//        byte[] spkiEncoded = spki.getEncoded();
//
//        // Build PublicKey object
//        KeyFactory kf = KeyFactory.getInstance("Ed25519");
//        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(spkiEncoded));

//        System.out.println(pubKey);
//        System.out.println(pubKey.getClass());

        byte[] data = "Hello World!".getBytes();

        Signature signature = SecurityUtils.getSignature("Ed25519");
//        signature.initSign(keyPair.getPrivate());
        signature.initSign(privateKey);
        signature.update(data);

        byte[] sign = signature.sign();

        Signature verifyer = SecurityUtils.getSignature("Ed25519");
        verifyer.initVerify(pubKeyConvertedToBC);
        verifyer.update(data);
        boolean verify = verifyer.verify(sign);

        System.out.println(verify);
    }
}
