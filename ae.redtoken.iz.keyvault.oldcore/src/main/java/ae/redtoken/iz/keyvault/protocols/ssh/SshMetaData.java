package ae.redtoken.iz.keyvault.protocols.ssh;

import ae.redtoken.iz.keyvault.protocols.AbstractMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class SshMetaData extends AbstractMetaData {
    public SshMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
        super(publicKeyMetadata);
    }

    public SshMetaData() {
    }
}
