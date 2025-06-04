package ae.redtoken.iz.keyvault;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public class TestSuite {
    @Test
    void testZool() throws IOException, InterruptedException {
        String walletRoot = "/tmp/xzy-wallet/";
        Runtime.getRuntime().exec(String.format("rm -rf " + walletRoot)).waitFor();
        final String exportRoot = "/tmp/export";
        Runtime.getRuntime().exec(String.format("rm -rf " + exportRoot)).waitFor();
        new File(exportRoot).mkdirs();

        // Create the master-seed
        // parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll
        String seed = "parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll";

        new File(walletRoot).mkdirs();
        Path masterSeed = Path.of(walletRoot, "master-seed");
//        Files.write(masterSeed, seed.getBytes());

        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"master-seed", "create", "--master-seed-file", masterSeed.toString()}));

//        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"master-seed", "create", "--vault-root=" + walletRoot}));
//        Assertions.assertTrue(new File(walletRoot).exists());
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"sub-seed", "create", "--master-seed-file", masterSeed.toString(), "--vault-root=" + walletRoot}));

        // Create an identity
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"identity", "create", "--id=alice@atlanta.com", "--name=Alice", "--vault-root=" + walletRoot}));

        // Create a ssh key
//        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "create", "--id=alice@atlanta.com", "--vault-root=" + walletRoot}));
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "create", "--alg=ed25519", "--vault-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "export", "--to-dir", exportRoot, "--vault-root=" + walletRoot}));

        // Create a nostr key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "create", "--vault-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "export", "--to-dir", exportRoot, "--vault-root=" + walletRoot}));

        // Create a openpgp key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"openpgp-keypair", "create", "--vault-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"openpgp-keypair", "export", "--to-dir", exportRoot, "--vault-root=" + walletRoot, "--password=pass"}));
    }
}
