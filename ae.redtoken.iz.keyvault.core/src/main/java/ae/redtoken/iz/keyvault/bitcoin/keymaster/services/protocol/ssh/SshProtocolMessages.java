package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

public class SshProtocolMessages {

    public record SshGetPublicKeyAccept(String pubKey) {
    }

    public record SshSignEventRequest(String event) {
    }

    public record SshSignEventAccept(String eventWithSignature) {
    }
}
