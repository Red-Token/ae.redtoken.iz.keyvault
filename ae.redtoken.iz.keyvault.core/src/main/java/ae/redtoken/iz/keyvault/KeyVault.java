package ae.redtoken.iz.keyvault;

import ae.redtoken.util.WalletHelper;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.util.logging.Logger;

/**
 * A blockzone (user) wallet contains a master-seed TODO: rename master-seed to steurer seed)
 * that in turn generate a subset of identity seeds, these identity seeds would then in turn generate protocol seeds.
 * It also connects a blkzn client, that has a btc wallet connected to it. The blkzn client in tur then generate a UserController (ZoneController or ServiceController) That controls
 * the relevant entity. So there is one blkzn client per wallet, and it supports controlling multiple entities with its controllers. TODO: The BlkZn Wallet should be renamed
 */
public class KeyVault {
    private static final Logger log
            = Logger.getLogger(KeyVault.class.getName());
    static final int SEED_SIZE = 32;

    public void saveMnemonicWordsToFile(File seedFile) {
        WalletHelper.writeMnemonicWordsToFile(seed, seedFile);
    }

//    public Identity restoreIdentity(String id, String name) {
//        Identity identity = new Identity(this, id, name);
////        identity.uc = client.client.getUserController(id);
//
//        identity.restoreAll();
//        return identity;
//    }

    public Identity createIdentity(String idString, String name) {
        return new Identity(this, idString, name);
    }

    final DeterministicSeed seed;

    //    protected final IGrantFinder gf;

    protected KeyVault(DeterministicSeed seed) {
        this.seed = seed;

        // TODO: have this checked
        // Now we create the subseed for blkzn using a fixed string.
    }

    public static KeyVault fromRandomSeed() {
        return new KeyVault(WalletHelper.generateDeterministicSeed(SEED_SIZE));
    }

    public static KeyVault fromSeedFile(File seedFile) {
        return new KeyVault(WalletHelper.readMnemonicWordsFromFile(seedFile));
    }
}
