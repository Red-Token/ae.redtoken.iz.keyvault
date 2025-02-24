package ae.redtoken.iz.keyvault;

import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class TestRandom2 {

    @Test
    void testRandom2() {

        String seed2 = "parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll";

        DeterministicSeed ds = DeterministicSeed.ofMnemonic(seed2, "");

        byte[] seedBytes = ds.getSeedBytes();
        assert seedBytes != null;

        SecureRandom random = new ChaCha20SecureRandom(seedBytes);

        for(int i = 0; i < 1000; i++) {
            random.nextLong();
        }

        Assertions.assertEquals(6277176432970049196L, random.nextLong());
    }
}
