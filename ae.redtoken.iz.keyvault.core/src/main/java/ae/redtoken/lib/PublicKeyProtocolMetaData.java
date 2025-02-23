package ae.redtoken.lib;

public class PublicKeyProtocolMetaData {
    public PublicKeyAlg pubAlg;
    public int pubBits;
//    public HashAlg hashAlg;
//    public int hashBits;

    public PublicKeyProtocolMetaData(String pubAlg, int pubBits) {
//        this(PublicKeyAlg.valueOf(pubAlg),pubBits,HashAlg.valueOf(hashAlg),hashBits);
        this(PublicKeyAlg.valueOf(pubAlg), pubBits);

    }

    public PublicKeyProtocolMetaData(PublicKeyAlg pubAlg, int pubBits) {
        this.pubAlg = pubAlg;
        this.pubBits = pubBits;
//        this.hashAlg = hashAlg;
//        this.hashBits = hashBits;
    }

    public PublicKeyProtocolMetaData() {
    }
}