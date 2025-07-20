package ae.redtoken.iz.keyvault.bitcoin.protocol;

import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;

import java.util.Collection;
import java.util.Map;

public class BitcoinProtocol {

    public record GetWatchingKeyAccept(String watchingKey, Collection<ScriptType> scriptTypes, Network network) {
    }

    public record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
    }

    public record BitcoinTransactionSignatureAccept(byte[] tx) {
    }
}
