package ae.redtoken.iz.keyvault.protocols;

abstract public class AbstractProtocolMetaData {
    public static enum KeyAlg {
        RSA, DSA, ECDSA
    }

    public KeyAlg keyAlg;
    public Integer keySize;

    public AbstractProtocolMetaData(KeyAlg keyAlg, Integer keySize) {
        this.keyAlg = keyAlg;
        this.keySize = keySize;
    }

    protected AbstractProtocolMetaData() {
    }
}
