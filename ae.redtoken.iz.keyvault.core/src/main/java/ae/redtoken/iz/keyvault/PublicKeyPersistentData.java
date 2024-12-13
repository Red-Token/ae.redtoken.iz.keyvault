package ae.redtoken.iz.keyvault;

import org.blkzn.wallet.PublicKeyProtocolMetaData;

public class PublicKeyPersistentData {
    public PublicKeyProtocolMetaData metaData;
    public byte[] fingerprint;

    public PublicKeyPersistentData(PublicKeyProtocolMetaData metaData, byte[] fingerprint) {
        this.metaData = metaData;
        this.fingerprint = fingerprint;
    }

    public PublicKeyPersistentData() {
    }
}
