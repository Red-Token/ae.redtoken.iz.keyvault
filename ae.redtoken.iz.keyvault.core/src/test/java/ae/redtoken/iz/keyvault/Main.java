package ae.redtoken.iz.keyvault;

import net.schmizz.sshj.common.Buffer;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;


public class Main {





    public static void main(String[] args) throws Exception {
        // Generate an ed25519 key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
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

        byte[] b = new Buffer.PlainBuffer().putPublicKey(keyPair.getPublic()).getCompactData();
        String s = String.format("ssh-%s %s %s", "ed25519", Base64.getEncoder().encodeToString(b), email);


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


//    private static String generatePublicKeyPem(KeyPair keyPair) {
//        return PublicKeyEntry.toString(keyPair.getPublic());
//    }
}
