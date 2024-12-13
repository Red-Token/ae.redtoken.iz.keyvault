package ae.redtoken.iz.keyvault;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

public class TestSuite {

    @Test
    void testZool() throws IOException {
        String walletRoot = "/tmp/xzy-wallet/";
        Runtime.getRuntime().exec(String.format("rm -rf " + walletRoot));

        // Create the master-seed
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"master-seed", "create", "--wallet-root=" + walletRoot}));
        Assertions.assertTrue(new File(walletRoot).exists());

        // Create an identity
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"identity", "create", "--id=rene.malmgren@gmail.com", "--name=Rene Malmgren", "--wallet-root=" + walletRoot}));

        // Create a ssh key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "create", "--id=rene.malmgren@gmail.com", "--wallet-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"ssh-keypair", "export", "--id=rene.malmgren@gmail.com", "--wallet-root=" + walletRoot}));

        // Create a ssh key
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "create", "--id=rene.malmgren@gmail.com", "--wallet-root=" + walletRoot}));

        // Export
        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"nostr-keypair", "export", "--id=rene.malmgren@gmail.com", "--wallet-root=" + walletRoot}));
    }
}
