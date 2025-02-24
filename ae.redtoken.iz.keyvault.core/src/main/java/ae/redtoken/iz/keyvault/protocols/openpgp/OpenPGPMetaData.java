package ae.redtoken.iz.keyvault.protocols.openpgp;

import ae.redtoken.iz.keyvault.protocols.AbstractMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class OpenPGPMetaData extends AbstractMetaData {
    public long creationTime;

    public OpenPGPMetaData(PublicKeyProtocolMetaData publicKeyMetadata, long creationTime) {
        super(publicKeyMetadata);
        this.creationTime = creationTime;
    }

    public OpenPGPMetaData() {
        super();
    }
}
