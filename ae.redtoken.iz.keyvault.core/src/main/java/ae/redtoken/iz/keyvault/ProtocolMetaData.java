package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class ProtocolMetaData {
    public PublicKeyProtocolMetaData keyMetaData;
    public long creationTime;

    public ProtocolMetaData(PublicKeyProtocolMetaData keyMetaData, long creationTime) {
        this.keyMetaData = keyMetaData;
        this.creationTime = creationTime;
    }

    public ProtocolMetaData() {
    }
}
