package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocolls.AbstractCredentialsMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class SshMetaData extends AbstractCredentialsMetaData {
    public SshMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
        super(publicKeyMetadata);
    }

    public SshMetaData() {
    }
}
