package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import lombok.SneakyThrows;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.wallet.*;

import java.util.Collection;
import java.util.List;

public class KeyVault {
    private final Network network;
    private final DeterministicSeed seed;

    static DeterministicKeyChain createKeyChain(Network network, DeterministicSeed seed, ScriptType type) {
        KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;

        HDPath path = kcgs.accountPathFor(type, network);
        DeterministicKeyChain dkc = DeterministicKeyChain.builder()
                .seed(seed)
                .outputScriptType(type)
                .accountPath(path)
                .build();

        dkc.setLookaheadSize(100);
        dkc.maybeLookAhead();

        return dkc;
    }

    public KeyVault(Network network, DeterministicSeed seed) {
        this.network = network;
        this.seed = seed;
    }

    public String getWatchingKey(ScriptType scriptType) {
        DeterministicKeyChain kcg = createKeyChain(network, seed, scriptType);

        DeterministicKey key = kcg
                .getWatchingKey()
                .dropParent()
                .dropPrivateBytes();

        return key.serializePubB58(network);
    }

    @SneakyThrows
    public ECKey.ECDSASignature sign(Sha256Hash input, byte[] pubKeyHash, ScriptType scriptType) {
        DeterministicKeyChain dkc = createKeyChain(network, seed, scriptType);

        DeterministicKey keyFromPubHash = dkc.findKeyFromPubHash(pubKeyHash);

        ECKey.ECDSASignature sign = keyFromPubHash.sign(input);
        byte[] bytes = sign.encodeToDER();

        return ECKey.ECDSASignature.decodeFromDER(bytes);
    }
}
