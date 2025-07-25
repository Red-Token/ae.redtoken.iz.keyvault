package ae.redtoken.iz.keyvault.bitcoin.protocol;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;

import java.util.Collection;
import java.util.Map;

public class BitcoinProtocolM {

    public record GetWatchingKeyAccept(String watchingKey, Collection<ScriptType> scriptTypes, BitcoinNetwork network) {
    }

    public record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
    }

    public record BitcoinTransactionSignatureAccept(byte[] tx) {
    }
}
