package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;

import java.util.Collection;
import java.util.Map;

public class BitcoinProtocolMessages {

    public record GetWatchingKeyAccept(String watchingKey, Collection<ScriptType> scriptTypes, BitcoinNetwork network) {
    }

    public record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
    }

    public record BitcoinTransactionSignatureAccept(byte[] tx) {
    }
}
