package ae.redtoken.iz.keyvault;

import ae.redtoken.util.WalletHelper;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class TestDOIT {

    @Test
    void name() {

        int size = 32;
        String passphrase = "";
        DeterministicSeed ds = WalletHelper.generateDeterministicSeed(size, passphrase);

        System.out.println(ds.getMnemonicString());

        Assertions.assertNotNull(ds.getMnemonicCode());
        DeterministicSeed ds2 = DeterministicSeed.ofMnemonic(ds.getMnemonicCode(), passphrase);

        NetworkParameters np = RegTestParams.get();

        // Create the key chain directly
        DeterministicKeyChain keyChain = DeterministicKeyChain.builder()
                .seed(ds2)
                .outputScriptType(ScriptType.P2WPKH)
                .build();



//        Wallet.fromSeed(np, ds2, outputScriptType, KeyChainGroupStructure.BIP32);
//
//
//        // Build the wallet manually with the key chain
//        Wallet wallet = Wallet.Builder.builder()
//                .fromKeys(params, keyChain)
//                .build();
    }
}
