package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

public class SshProtocolMessages {

    public record SshGetPublicKeyAccept(String pubKey) {
    }

    public record SshSignEventRequest(byte[] publicKey, byte[] data) {
    }

    public record SshSignEventAccept(String signature) {
    }
}
