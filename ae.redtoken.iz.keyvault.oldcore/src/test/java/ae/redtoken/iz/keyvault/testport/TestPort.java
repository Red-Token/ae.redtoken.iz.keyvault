package ae.redtoken.iz.keyvault.testport;

import ae.redtoken.util.Util;
import ae.redtoken.util.WalletHelper;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

public class TestPort {

    @Test
    void testMnemonic() {

        String word = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";

        DeterministicSeed ds = DeterministicSeed.ofMnemonic(word, "");

        System.out.println(Util.bytesToHex(ds.getSeedBytes()));

        String sub = "rene.malmgren@gmail.com";

        DeterministicSeed subSeed = WalletHelper.createSubSeed(ds, sub, "");

        System.out.println(subSeed.getMnemonicString());

        System.out.println(Util.bytesToHex(subSeed.getSeedBytes()));


    }
}
