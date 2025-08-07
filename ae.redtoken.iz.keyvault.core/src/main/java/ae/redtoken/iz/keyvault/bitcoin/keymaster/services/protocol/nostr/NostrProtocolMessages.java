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

    public record NostrDescribeMessageAccept(String[] result) {
    }

    public record NostrGetPublicKeyAccept(String pubKey) {
    }

    public record NostrSignEventRequest(String event) {
    }

    public record NostrSignEventAccept(String eventWithSignature) {
    }

    public record NostrNip44EncryptEventAccept(String encryptedMessage) {
    }

    public record NostrNip44DecryptEventAccept(String message) {
    }

    public record NostrNip44EncryptRequest(String pubKey, String counterPartyPubkey, String message) {
    }

    public record NostrNip44DecryptRequest(String pubKey, String counterPartyPubkey, String encryptedMessage) {
    }
}
