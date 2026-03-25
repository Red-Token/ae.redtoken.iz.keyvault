package ae.redtoken.iz.keyvault;

import ae.redtoken.util.PemHandler;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.io.pem.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;


public class Main {

    public static KeyPair convertToKeyPair(Ed25519PrivateKeyParameters privateKeyParams) throws GeneralSecurityException {

        byte[] xxxty = Base64.getDecoder().decode("AAAAC3NzaC1lZDI1NTE5AAAAIFzHRmJDd9Kb3mhHOqomV/9Gn4k9NLMCLAkZmkKImKA9");

        // Extract the raw key bytes
        byte[] privateKeyBytes = privateKeyParams.getEncoded();
        Ed25519PublicKeyParameters publicKeyParams = privateKeyParams.generatePublicKey();

        // This is the point on the curve calculated as 32 byte params
        byte[] publicKeyBytes = publicKeyParams.getEncoded();

        // Generate the PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = keyFactory.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(false, new BigInteger(publicKeyBytes))));

        try {
            byte[] out1 = OpenSSHPublicKeyUtil.encodePublicKey(publicKeyParams);
            byte[] out = OpenSSHPrivateKeyUtil.encodePrivateKey(privateKeyParams);

            // AAAAC3NzaC1lZDI1NTE5AAAAIFzHRmJDd9Kb3mhHOqomV/9Gn4k9NLMCLAkZmkKImKA9
            // AAAAC3NzaC1lZDI1NTE5AAAAIFzHRmJDd9Kb3mhHOqomV/9Gn4k9NLMCLAkZmkKImKA9

            String pout = new String(Base64.getEncoder().encode(out1));
            String pout2 = new String(Base64.getEncoder().encode(out));



            System.out.println(pout2);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


//        return privateKey;
//
//        // Generate the PublicKey
//        PublicKey publicKey = keyFactory.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(false, publicKeyBytes)));
//
        return new KeyPair(publicKey, privateKey);
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair1 = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();

        keyPair1.getPublic().getFormat();

        Security.addProvider(new BouncyCastleProvider());

        byte[] blob = new PemReader(new FileReader("/home/rene/.ssh/id_ed25519")).readPemObject().getContent();

        // This here will give me the seed
        AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);

        Ed25519PrivateKeyParameters xt = (Ed25519PrivateKeyParameters) asymmetricKeyParameter;




        byte[] fp1 = xt.getEncoded();

        KeyPair kp = convertToKeyPair(xt);

        AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(kp.getPublic().getEncoded());
        byte[] b = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digest1 = digest.digest(b);

        byte[] fp2 = kp.getPrivate().getEncoded();



        kp.getPrivate().getEncoded();
        String format = kp.getPrivate().getFormat();

        OpenSSHPrivateKeySpec openSSHPrivateKeySpec = new OpenSSHPrivateKeySpec(blob);

        Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
        String pemString = generatePrivateKeyPem(kp);

        JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(kp.getPrivate(), null);
        PemWriter pw = new PemWriter(new StringWriter());
        pw.writeObject(pkcs8Generator);

        PrivateKeyInfo pki2 = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        AsymmetricKeyParameter key = PrivateKeyFactory.createKey(pki2);
        byte[] bytes222 = OpenSSHPrivateKeyUtil.encodePrivateKey(key);
        PemHandler.writePem(new FileWriter("test4.xx"), "OPENSSH PRIVATE KEY", bytes222);

        PemObject po = new PemObject("PRIVATE KEY", kp.getPrivate().getEncoded());

        PEMParser parser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemString.getBytes())));
        Object o = parser.readObject();

        if ((o instanceof PrivateKeyInfo)) {
            PrivateKeyInfo pki = (PrivateKeyInfo) o;
            AsymmetricKeyParameter key2 = PrivateKeyFactory.createKey(pki);
            byte[] bytes = OpenSSHPrivateKeyUtil.encodePrivateKey(key2);
            PemHandler.writePem(new FileWriter("test3.xx"), "OPENSSH PRIVATE KEY", bytes);



            System.out.println("sfsdfdsfsdfsdfs");
        }

        Ed25519PrivateKeyParameters xt2 = new Ed25519PrivateKeyParameters(kp.getPrivate().getEncoded());

        byte[] bytes1 = OpenSSHPrivateKeyUtil.encodePrivateKey(xt2);

        PemHandler.writePem(new FileWriter("test2.xx"), "TEST", bytes1);

        OpenSSHPrivateKeyUtil.encodePrivateKey(xt2);

        byte[] blob2 = OpenSSHPrivateKeyUtil.encodePrivateKey(asymmetricKeyParameter);

        PemHandler.writePem(new FileWriter("test.xx"), "TEST", blob2);


        PemWriter pemWriter = new PemWriter(new FileWriter("test2.xx"));

        FileKeyPairProvider fkp = new FileKeyPairProvider(Paths.get("/home/rene/.ssh/id_ed25519"));

        // Read key pairs
        Iterable<KeyPair> keyPairs = fkp.loadKeys(null);

        Ed25519PrivateKeyParameters keyParams = new Ed25519PrivateKeyParameters(new byte[32], 0);
        byte[] bytes = OpenSSHPrivateKeyUtil.encodePrivateKey(keyParams);

        String z = new String(bytes, StandardCharsets.UTF_8);

        keyPairs.forEach(keyPair -> {
            System.out.println(keyPair.getPublic());

            String s = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
        });


        // Generate an ed25519 key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Write the private key to a PEM file
        String privateKeyPem = generatePrivateKeyPem(keyPair);
        try (FileWriter writer = new FileWriter("id_ed25519")) {
            writer.write(privateKeyPem);
        }

        // Write the public key to a PEM file
        String publicKeyPem = generatePublicKeyPem(keyPair);
        try (FileWriter writer = new FileWriter("id_ed25519.pub")) {
            writer.write(publicKeyPem);
        }

        String email = "redtoken@redtoken.com";

        savePublicKeyToFile(keyPair, "zool.pub");

//        byte[] b = new Buffer.PlainBuffer().putPublicKey(keyPair.getPublic()).getCompactData();
//        BCEdDSAPublicKey ed25519PublicKey = (BCEdDSAPublicKey) keyPair.getPublic();
//        String s = String.format("ssh-%s %s %s", "ed25519", Base64.getEncoder().encodeToString(ed25519PublicKey.getEncoded()), email);
//
//        System.out.println(s);


        System.out.println("SSH key pair generated successfully!");
        System.out.println("Private key saved to: id_ed25519");
        System.out.println("Public key saved to: id_ed25519.pub");
    }

    private static String generatePrivateKeyPem(KeyPair keyPair) throws IOException, OperatorCreationException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(keyPair.getPrivate(), null);
            pemWriter.writeObject(pkcs8Generator);
        }
        return stringWriter.toString();
    }

    private static String generatePublicKeyPem(KeyPair keyPair) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(keyPair.getPublic());
            pemWriter.writeObject(pemGenerator);
        }
        return stringWriter.toString();
    }

    private static void savePublicKey(KeyPair keyPair) throws Exception {
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);

        // OpenSSH public key format
        String publicKeyFormat = "ssh-ed25519 " + publicKeyBase64 + " user@host";

        Files.write(Paths.get("id_ed25519.pub"), publicKeyFormat.getBytes());
        System.out.println("Saved public key: id_ed25519.pub");
    }

    private static void savePublicKeyToFile(KeyPair keyPair, String filename) throws IOException {
        try {
            savePublicKey(keyPair);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


//    private static String generatePublicKeyPem(KeyPair keyPair) {
//        return PublicKeyEntry.toString(keyPair.getPublic());
//    }
}
