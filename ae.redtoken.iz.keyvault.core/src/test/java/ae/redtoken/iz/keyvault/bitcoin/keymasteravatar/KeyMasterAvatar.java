package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.BitcoinMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMaster;
import ae.redtoken.iz.keyvault.bitcoin.protocol.BitcoinProtocol;
import org.bitcoinj.base.Network;
import org.bitcoinj.crypto.DeterministicKey;

import java.util.Collection;

import static ae.redtoken.iz.keyvault.bitcoin.TestWallet.fromWatchingKey;

public class KeyMasterAvatar {

    public class IdentityAvatar {
        final TestWallet.Identity identity;

        public IdentityAvatar(TestWallet.Identity identity) {
            this.identity = identity;
        }

        public class BitcoinProtocolAvatar {
            public BitcoinAvatarService createBitcoinAvatarService(BitcoinMasterService masterService) {
                BitcoinProtocol.GetWatchingKeyAccept wk = masterService.getWatchingKey();
                DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey(), wk.network());
                return fromWatchingKey(wk.network(), watchingKey, wk.scriptTypes(), masterService);
            }
        }
    }

    final KeyMaster keyMaster;

    public KeyMasterAvatar(KeyMaster keyMaster) {
        this.keyMaster = keyMaster;
    }

    Collection<TestWallet.Identity> getIdentities() {
        return keyMaster.getIdentities();
    }

    public TestWallet.Identity getDefaultIdentity() {
        return keyMaster.getDefaultIdentity();
    }

}
