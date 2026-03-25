package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.RedeemData;
import org.bitcoinj.wallet.Wallet;

class RemoteWallet extends Wallet {

    public RemoteWallet(Network network, KeyChainGroup keyChainGroup) {
        super(network, keyChainGroup);
    }

    public boolean canSignFor(Script script) {
        if (ScriptPattern.isP2PK(script)) {
            byte[] pubkey = ScriptPattern.extractKeyFromP2PK(script);
            ECKey key = this.findKeyFromPubKey(pubkey);
            return key != null;
        } else if (ScriptPattern.isP2SH(script)) {
            RedeemData data = this.findRedeemDataFromScriptHash(ScriptPattern.extractHashFromP2SH(script));
            return data != null && this.canSignFor(data.redeemScript);
        } else if (ScriptPattern.isP2PKH(script)) {
            ECKey key = this.findKeyFromPubKeyHash(ScriptPattern.extractHashFromP2PKH(script), ScriptType.P2PKH);
            return key != null;
        } else if (ScriptPattern.isP2WPKH(script)) {
            ECKey key = this.findKeyFromPubKeyHash(ScriptPattern.extractHashFromP2WH(script), ScriptType.P2WPKH);
            return key != null && key.isCompressed();
        } else {
            if (ScriptPattern.isSentToMultisig(script)) {
                for (ECKey pubkey : script.getPubKeys()) {
                    ECKey key = this.findKeyFromPubKey(pubkey.getPubKey());
                    if (key != null) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
