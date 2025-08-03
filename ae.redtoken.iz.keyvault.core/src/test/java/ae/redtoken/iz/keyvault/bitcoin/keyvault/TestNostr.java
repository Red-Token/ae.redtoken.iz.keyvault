package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Test;

public class TestNostr {

    static class TestFactory {
        public static DeterministicSeed createTestDeterministicSeed() {
            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            return DeterministicSeed.ofMnemonic(mn, "");
        }
    }


    @Test
    void testNostr() {
        DeterministicSeed ds = TestFactory.createTestDeterministicSeed();
        KeyVault kv = new KeyVault(ds);
//        KeyVault.KeyPath keyPath = new KeyVault.KeyPath();
//
//        kv.execute(, new KeyVault.GetPublicKeyNostrKeyVaultCall.GetPublicKeyNostrCallConfig());





    }
}
