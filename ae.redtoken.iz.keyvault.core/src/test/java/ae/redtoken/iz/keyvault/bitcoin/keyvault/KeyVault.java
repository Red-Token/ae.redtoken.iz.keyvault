package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import lombok.SneakyThrows;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.wallet.*;

import java.util.Collection;
import java.util.List;

public class KeyVault {
//    private final KeyChainGroup kcg;
    private final Network network;
    private final DeterministicSeed seed;
    private final Collection<ScriptType> scriptTypes;

    static KeyChainGroup createKeyChainGroup(Network network, DeterministicSeed seed, Collection<ScriptType> scriptTypes) {
        KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;

        List<DeterministicKeyChain> keyChains = scriptTypes.stream().map(type -> DeterministicKeyChain.builder()
                .seed(seed)
                .outputScriptType(type)
                .accountPath(kcgs.accountPathFor(type, network))
                .build()).toList();

        keyChains.forEach(kc -> {
            kc.setLookaheadSize(100);
            kc.maybeLookAhead();
        });

        return KeyChainGroup.builder(network, kcgs).chains(keyChains).build();
    }

    public KeyVault(Network network, DeterministicSeed seed, Collection<ScriptType> scriptTypes) {
        this.network = network;
        this.seed = seed;
        this.scriptTypes = scriptTypes;
    }

    public String getWatchingKey() {
        KeyChainGroup kcg = createKeyChainGroup(network, seed, scriptTypes);
        DeterministicKey key = kcg.getActiveKeyChain()
                .getWatchingKey()
                .dropParent()
                .dropPrivateBytes();

        return key.serializePubB58(network);
    }

    @SneakyThrows
    public ECKey.ECDSASignature sign(Sha256Hash input, byte[] pubKeyHash) {
        KeyChainGroup kcg = createKeyChainGroup(network, seed, scriptTypes);
        DeterministicKey keyFromPubHash = kcg.getActiveKeyChain().findKeyFromPubHash(pubKeyHash);
        ECKey.ECDSASignature sign = keyFromPubHash.sign(input);
        byte[] bytes = sign.encodeToDER();
        return ECKey.ECDSASignature.decodeFromDER(bytes);
    }
}
