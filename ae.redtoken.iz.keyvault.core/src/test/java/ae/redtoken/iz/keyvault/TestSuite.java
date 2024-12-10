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

        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"master-seed", "create", "--wallet-root=" + walletRoot}));
        Assertions.assertTrue(new File(walletRoot).exists());

        Assertions.assertEquals(0, KeyVaultMain.call(new String[]{"identity", "create", "--id=rene.malmgren@gmail.com", "--name=Rene Malmgren", "--wallet-root=" + walletRoot}));
    }
}
