package ae.redtoken.iz.keyvault.protocols.bitcoin;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.SigNetParams;

import java.util.Arrays;

public enum BitcoinNetwork {
    regtest(RegTestParams.get()), mainnet(MainNetParams.get()), signet(SigNetParams.get());


    public final NetworkParameters params;

    BitcoinNetwork(NetworkParameters params) {
        this.params = params;
    }


    public static BitcoinNetwork getFromParams(NetworkParameters params) {
        return Arrays.stream(BitcoinNetwork.values())
                .filter(t -> t.params == params)
                .findFirst()
                .orElseThrow(IllegalStateException::new);
    }
}
