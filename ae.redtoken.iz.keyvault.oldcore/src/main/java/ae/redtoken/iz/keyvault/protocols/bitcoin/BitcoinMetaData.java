package ae.redtoken.iz.keyvault.protocols.bitcoin;

import ae.redtoken.iz.keyvault.protocols.AbstractProtocolMetaData;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.SigNetParams;

public class BitcoinMetaData extends AbstractProtocolMetaData {

    public enum BitcoinNetwork {
        regtest(RegTestParams.get()), mainnet(MainNetParams.get()), signet(SigNetParams.get());


        public final NetworkParameters params;

        BitcoinNetwork(NetworkParameters params) {
            this.params = params;
        }
    }

    public BitcoinNetwork network;
    public ScriptType scriptType;

    public BitcoinMetaData(BitcoinNetwork network, ScriptType scriptType) {
        super(KeyAlg.ECDSA, null);
        this.network = network;
        this.scriptType = scriptType;
    }

    protected BitcoinMetaData() {
    }
}
