package ae.redtoken.iz.keyvault;

import ae.redtoken.util.WalletHelper;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.util.logging.Logger;

public class KeyVault {
    private static final Logger log
            = Logger.getLogger(KeyVault.class.getName());
    static final int SEED_SIZE = 32;

    final DeterministicSeed seed;

    protected KeyVault(DeterministicSeed seed) {
        this.seed = seed;
    }

    public static KeyVault fromRandomSeed() {
        return new KeyVault(WalletHelper.generateDeterministicSeed(SEED_SIZE, ""));
    }

    public static KeyVault fromSeedFile(File seedFile, String passphrase) {
        return new KeyVault(WalletHelper.readMnemonicWordsFromFile(seedFile,passphrase));
    }
}
