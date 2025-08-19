package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;

public record SshConfiguration(SshKeyType type, int size) {
}

