package ae.redtoken.iz.keyvault;

public class PublicKeyPersistentData {
    public ProtocolMetaData metaData;
    public byte[] fingerprint;

    public PublicKeyPersistentData(ProtocolMetaData metaData, byte[] fingerprint) {
        this.metaData = metaData;
        this.fingerprint = fingerprint;
    }

    public PublicKeyPersistentData() {
    }
}
