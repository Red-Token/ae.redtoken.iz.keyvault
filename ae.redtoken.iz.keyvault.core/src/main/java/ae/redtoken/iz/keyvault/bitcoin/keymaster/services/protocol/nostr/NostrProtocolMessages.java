package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;

import java.util.Collection;
import java.util.Map;

public class NostrProtocolMessages {
//    public record GetWatchingKeyAccept(String watchingKey, Collection<ScriptType> scriptTypes, BitcoinNetwork network) {
//    }
//
//    public record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
//    }
//
//    public record BitcoinTransactionSignatureAccept(byte[] tx) {
//    }

    public record NostrDescribeMessageAccept(String[] result) {}
    public record NostrGetPublicKeyAccept(String pubKey) {}

    public record NostrSignEventRequest(String event) {}
    public record NostrSignEventAccept(String eventWithSignature) {}
}
