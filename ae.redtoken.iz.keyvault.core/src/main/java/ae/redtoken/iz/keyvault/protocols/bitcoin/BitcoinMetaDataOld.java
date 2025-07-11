package ae.redtoken.iz.keyvault.protocols.bitcoin;

import ae.redtoken.iz.keyvault.protocols.AbstractMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.KeyChain;

public class BitcoinMetaDataOld extends AbstractMetaData {

    public BitcoinNetwork network;
    public ScriptType scriptType;
    public KeyChain.KeyPurpose purpose;

    public BitcoinMetaDataOld(PublicKeyProtocolMetaData publicKeyMetadata, BitcoinNetwork network, ScriptType scriptType, KeyChain.KeyPurpose purpose) {
        super(publicKeyMetadata);
        this.network = network;
        this.scriptType = scriptType;
        this.purpose = purpose;
    }

    public BitcoinMetaDataOld() {
        super();
    }
}
