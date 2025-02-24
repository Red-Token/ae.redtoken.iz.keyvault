package ae.redtoken.iz.keyvault.protocols;

import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class AbstractMetaData {
    public PublicKeyProtocolMetaData publicKeyMetadata;
    public byte[] fingerprint;

    public AbstractMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
        this.publicKeyMetadata = publicKeyMetadata;
    }

    public AbstractMetaData() {
    }
}
