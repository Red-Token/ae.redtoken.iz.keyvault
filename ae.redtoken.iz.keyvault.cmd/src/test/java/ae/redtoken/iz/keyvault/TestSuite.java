package ae.redtoken.iz.keyvault;

import com.google.common.io.Files;
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
        final String exportRoot =  "/tmp/export";
        Runtime.getRuntime().exec(String.format("rm -rf " + exportRoot)).waitFor();
        new File(exportRoot).mkdirs();

        // Create the master-seed
        // parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll
        String seed = "parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll";

        new File(walletRoot).mkdirs();
        Files.write(seed.getBytes(), Path.of(walletRoot, "seed").toFile());

//        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"master-seed", "create", "--wallet-root=" + walletRoot}));
//        Assertions.assertTrue(new File(walletRoot).exists());

        // Create an identity
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"identity", "create", "--id=alice@atlanta.com", "--name=Alice", "--wallet-root=" + walletRoot}));

        // Create a ssh key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "create", "--id=alice@atlanta.com", "--wallet-root=" + walletRoot}));
//        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "create", "--id=alice@atlanta.com","--alg=ed25519", "--wallet-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "export", "--id=alice@atlanta.com", "--to-dir", exportRoot, "--wallet-root=" + walletRoot}));

        // Create a nostr key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "create", "--id=alice@atlanta.com", "--wallet-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "export", "--id=alice@atlanta.com", "--to-dir", exportRoot, "--wallet-root=" + walletRoot}));

        // Create a openpgp key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"openpgp-keypair", "create", "--id=alice@atlanta.com", "--wallet-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"openpgp-keypair", "export", "--id=alice@atlanta.com", "--to-dir", exportRoot, "--wallet-root=" + walletRoot, "--password=pass"}));
    }
}
