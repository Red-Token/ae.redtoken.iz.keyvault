package ae.redtoken.iz.keyvault.protocolls;

import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class AbstractCredentialsMetaData {
    public PublicKeyProtocolMetaData publicKeyMetadata;
    public byte[] fingerprint;

    public AbstractCredentialsMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
        this.publicKeyMetadata = publicKeyMetadata;
    }

    public AbstractCredentialsMetaData() {
    }
}
