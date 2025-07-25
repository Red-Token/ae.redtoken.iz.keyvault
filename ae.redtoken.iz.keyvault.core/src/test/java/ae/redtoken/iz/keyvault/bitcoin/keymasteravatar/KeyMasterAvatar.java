package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.protocol.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.BitcoinMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.protocol.BitcoinProtocolM;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.KeyChainGroup;

import java.util.Collection;
import java.util.List;

public class KeyMasterAvatar {

    public static BitcoinAvatarService fromWatchingKey(Network network, DeterministicKey watchKey, Collection<ScriptType> outputScriptTypes, BitcoinMasterService masterService) {
        List<DeterministicKeyChain> chains = outputScriptTypes.stream()
                .map(type ->
                        DeterministicKeyChain.builder()
                                .watch(watchKey)
                                .outputScriptType(type)
                                .build())
                .toList();
        return new BitcoinAvatarService(network, KeyChainGroup.builder(network).chains(chains).build(), masterService);
    }

    public class IdentityAvatar {
        final IdentityStackedService identity;

        public IdentityAvatar(IdentityStackedService identity) {
            this.identity = identity;
        }

        public class BitcoinProtocolAvatar {
            public BitcoinAvatarService createBitcoinAvatarService(BitcoinMasterService masterService) {
                BitcoinProtocolM.GetWatchingKeyAccept wk = masterService.getWatchingKey();
                DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey(), wk.network());
                return fromWatchingKey(wk.network(), watchingKey, wk.scriptTypes(), masterService);
            }
        }
    }

    final KeyMasterStackedService keyMaster;

    public KeyMasterAvatar(KeyMasterStackedService keyMaster) {
        this.keyMaster = keyMaster;
    }

    public IdentityAvatar getDefaultIdentity() {

        return new IdentityAvatar((IdentityStackedService) keyMaster.subServices.get(keyMaster.getDefaultId()));
//        return keyMaster.getDefaultId();
    }

//    Collection<IdentityStackedService> getIdentities() {
//        return keyMaster.getIdentities();
//    }
//
//    public IdentityStackedService getDefaultIdentity() {
//        return keyMaster.getDefaultIdentity();
//    }

}
