package ae.redtoken.iz.keyvault;

import ae.redtoken.cf.sm.ssh.SshExporter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class TestOpenSSH {

    @Test
    void testCreate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        System.out.println(keyPair.getPublic().getFormat());
        System.out.println(keyPair.getPublic().getAlgorithm());

        Path testRoot = Files.createTempDirectory("testOpenSshExporter");
        SshExporter se = new SshExporter(keyPair, testRoot, "test@zool.com");
        se.exportPrivateKey();
        se.exportPublicKey();
    }
}
