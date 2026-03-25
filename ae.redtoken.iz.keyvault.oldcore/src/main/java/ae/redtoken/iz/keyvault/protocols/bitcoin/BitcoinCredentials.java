package ae.redtoken.iz.keyvault.protocols.bitcoin;

import ae.redtoken.iz.keyvault.AbstractCredentials;
import ae.redtoken.iz.keyvault.AbstractPublicKeyCredentials;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.Network;
import org.bitcoinj.crypto.DeterministicKey;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Objects;

public class BitcoinCredentials extends AbstractCredentials {

    private final BitcoinConfiguration configuration;

    static class BitcoinCredentialsPersistentData {
        byte[] fingerprint;
    }

    abstract static class AbstractWrappedKey implements Key {
        public final DeterministicKey key;
        protected final Network network;

        AbstractWrappedKey(DeterministicKey key, Network network) {
            this.key = key;
            this.network = network;
        }

        @Override
        public String getAlgorithm() {
            return "ECDSA";
        }

        @Override
        public String getFormat() {
            return "Base58";
        }
    }

    static class WrappedPublicKey extends AbstractWrappedKey implements PublicKey {
        WrappedPublicKey(DeterministicKey key, Network network) {
            super(key, network);
        }

        @Override
        public byte[] getEncoded() {
            return key.serializePubB58(this.network).getBytes(StandardCharsets.UTF_8);
        }
    }

    static class WrappedPrivateKey extends AbstractWrappedKey implements PrivateKey {
        WrappedPrivateKey(DeterministicKey key, Network network) {
            super(key, network);
        }

        @Override
        public byte[] getEncoded() {
            return key.serializePrivB58(this.network).getBytes(StandardCharsets.UTF_8);
        }
    }

    public final KeyPair kp;

    @SneakyThrows
    public BitcoinCredentials(BitcoinConfiguration configuration, File file) {
        this.configuration = configuration;
        ObjectMapper mapper = new ObjectMapper();
        BitcoinCredentialsPersistentData pd = mapper.readValue(file, BitcoinCredentialsPersistentData.class);
//        DeterministicKey dk1 = DeterministicKey.deserializeB58(new String(pd.fingerprint), configuration.metaData.network.params.network());
        DeterministicKey key = configuration.keyChain.findKeyFromPubHash(pd.fingerprint);
        this.kp = new KeyPair(
                new WrappedPublicKey(key.dropPrivateBytes(), configuration.metaData.network.params.network()),
                new WrappedPrivateKey(key, configuration.metaData.network.params.network()));
    }

    @SneakyThrows
    void persist(File file) {
        BitcoinCredentialsPersistentData pd = new BitcoinCredentialsPersistentData();
        DeterministicKey pubKey = ((WrappedPublicKey) kp.getPublic()).key;

//        DeterministicKey dk1 = DeterministicKey.deserializeB58(new String(kp.getPublic().getEncoded()), configuration.metaData.network.params.network());
        pd.fingerprint = pubKey.getPubKeyHash();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(file, pd);
    }

//    @Override
//    protected Class<BitcoinMetaDataOld> getMetaDataClass() {
//        return BitcoinMetaDataOld.class;
//    }
//
//    @Override
//    protected byte[] calculateFingerPrint(KeyPair keyPair) {
//        return LegacyAddress.fromBase58(new String(keyPair.getPublic().getEncoded()), metaData.network.params.network()).getHash();
//    }

//    static private byte[] getRawPrivateKey(ECPrivateKey privateKey) {
//        return NostrUtil.bytesFromBigInteger(privateKey.getS());
//    }
//
//
//    static private byte[] getRawPublicKey(ECPrivateKey privateKey) {
//        try {
//            return Schnorr.genPubKey(getRawPrivateKey(privateKey));
//
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }

//    @Override
//    // TODO Make this generic
//    protected KeyPairGenerator createKeyPairGenerator(SecureRandom sr) {
//        try {
//            Security.addProvider(new BouncyCastleProvider());
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
//            kpg.initialize(new ECGenParameterSpec("secp256k1"), sr);
//            return kpg;
//
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
//            throw new RuntimeException(e);
//        }
//    }

}
