package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IKeyMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IIdentityService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Avatar;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.KeyChainGroup;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class KeyMasterAvatar extends Avatar<KeyMasterStackedService> {

    public static BitcoinAvatarService fromWatchingKey(Network network, DeterministicKey watchKey, Collection<ScriptType> outputScriptTypes, IBitcoinConfigurationService masterService) {
        List<DeterministicKeyChain> chains = outputScriptTypes.stream()
                .map(type ->
                        DeterministicKeyChain.builder()
                                .watch(watchKey)
                                .outputScriptType(type)
                                .build())
                .toList();
        return new BitcoinAvatarService(network, KeyChainGroup.builder(network).chains(chains).build(), masterService);
    }

    static class NestedAvatar<A extends IStackedService> {
        private final List<String> fullId;
        public final A service;

        public NestedAvatar(List<String> fullId, A service) {
            this.fullId = fullId;
            this.service = service;
        }

        public String getId() {
            return fullId.getLast();
        }

        public List<String> subId(String id) {
            List<String> tmp = new ArrayList<>(fullId);
            tmp.add(id);
            return List.copyOf(tmp);
        }
    }

    public class IdentityAvatar extends NestedAvatar<IIdentityService> {
        public IdentityAvatar(List<String> id) {
            super(id, createProxy(id.toArray(new String[0]), IIdentityService.class));
        }

        public class BitcoinProtocolAvatar extends NestedAvatar<IStackedService> {
//            final IStackedService protocol;
//            final String id;

//            public BitcoinProtocolAvatar() {
//                this(BitcoinProtocolStackedService.PROTOCOL_ID);
//            }

            public BitcoinProtocolAvatar(List<String> fullId) {
                super(fullId, createProxy(fullId.toArray(new String[0]), IStackedService.class));
            }

            public class BitcoinConfigurationAvatar {
                IBitcoinConfigurationService bitcoinConfigurationService;
                public final BitcoinAvatarService service;
                public final String id;

                public BitcoinConfigurationAvatar(List<String> fullId) {
                    this(fullId.getLast(), createProxy(fullId, IBitcoinConfigurationService.class));
                }

                public BitcoinConfigurationAvatar(String id, IBitcoinConfigurationService bitcoinConfigurationService) {
                    this.id = id;
                    this.bitcoinConfigurationService = bitcoinConfigurationService;
                    this.service = createBitcoinAvatarService(bitcoinConfigurationService);
                }

                static public BitcoinAvatarService createBitcoinAvatarService(IBitcoinConfigurationService bitcoinConfigurationService) {
                    BitcoinProtocolMessages.GetWatchingKeyAccept wk = bitcoinConfigurationService.getWatchingKey();

                    DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey(), wk.network());
                    return fromWatchingKey(wk.network(), watchingKey, wk.scriptTypes(), bitcoinConfigurationService);
                }
            }
        }
    }

    final KeyMasterStackedService keyMaster;
    public final IKeyMasterService service;

    public KeyMasterAvatar(KeyMasterRunnable keyMasterRunnable) {
        this.masterRunnable = keyMasterRunnable;
        this.keyMaster = masterRunnable.rootStackedService;
        this.service = createProxy(new String[0], IKeyMasterService.class);
    }

//    public IdentityAvatar getDefaultIdentity() {
//
//        return new IdentityAvatar((IdentityStackedService) keyMaster.subServices.get(keyMaster.getDefaultId()));
////        return keyMaster.getDefaultId();
//    }

//    Collection<IdentityStackedService> getIdentities() {
//        return keyMaster.getIdentities();
//    }
//
//    public IdentityStackedService getDefaultIdentity() {
//        return keyMaster.getDefaultIdentity();
//    }

}
