package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import ae.redtoken.iz.keyvault.protocols.nostr.NostrCredentials;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrMetaData;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import nostr.crypto.schnorr.Schnorr;
import nostr.encryption.MessageCipher;
import nostr.encryption.nip44.MessageCipher44;
import nostr.util.NostrUtil;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroupStructure;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class KeyVault {

    public record KeyPath(byte[] identity, byte[] protocol, byte[] config) {
    }

    public abstract class AbstractKeyVaultCall<A extends AbstractKeyVaultCall.AbstractCallConfig> {
        public abstract static class AbstractCallConfig {
            final int callId;

            AbstractCallConfig(int callId) {
                this.callId = callId;
            }
        }

        protected final DeterministicSeed seed;
        protected final A config;

        public AbstractKeyVaultCall(KeyPath path, A config) {
            this.seed = generateSeed(path);
            this.config = config;
        }

        abstract byte[] execute();
    }

    abstract class NostrKeyVaultCall<A extends NostrKeyVaultCall.AbstractNostrCallConfig> extends AbstractKeyVaultCall<A> {
        static int CALL_ID_OFFSET = 0x4000;

        static class DeterministicNostrKeyFactory {
            final SecureRandom dsr;

            DeterministicNostrKeyFactory(DeterministicSeed seed) {
                this.dsr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);
            }

            @SneakyThrows
            byte[] generatePublicKey(int seq) {
                byte[] publicKeyBytes;

                do {
                    NostrCredentials credentials = new NostrCredentials(dsr, new NostrMetaData());
                    byte[] privateKeyBytes = NostrUtil.bytesFromBigInteger(((ECPrivateKey) credentials.kp.getPrivate()).getS());
                    publicKeyBytes = Schnorr.genPubKey(privateKeyBytes);

                } while (seq-- > 0);

                return publicKeyBytes;
            }

            @SneakyThrows
            byte[] generatePrivateKey(byte[] publicKey) {
                for (int i = 0; i < 100; i++) {
                    NostrCredentials credentials = new NostrCredentials(dsr, new NostrMetaData());
                    byte[] privateKeyBytes = NostrUtil.bytesFromBigInteger(((ECPrivateKey) credentials.kp.getPrivate()).getS());
                    byte[] publicKeyBytes = Schnorr.genPubKey(privateKeyBytes);

                    if (Arrays.equals(publicKeyBytes, publicKey)) {
                        return privateKeyBytes;
                    }
                }

                throw new RuntimeException("Out of tries");
            }
        }

        final DeterministicNostrKeyFactory dkf;

        public NostrKeyVaultCall(KeyPath path, A config) {
            super(path, config);
            dkf = new DeterministicNostrKeyFactory(seed);
        }

        abstract static class AbstractNostrCallConfig extends AbstractCallConfig {
            AbstractNostrCallConfig(int callId) {
                super(callId);
            }
        }
    }

    class GetPublicKeyNostrKeyVaultCall extends NostrKeyVaultCall<GetPublicKeyNostrKeyVaultCall.GetPublicKeyNostrCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0001;

        static class GetPublicKeyNostrCallConfig extends AbstractNostrCallConfig {
            GetPublicKeyNostrCallConfig() {
                super(CALL_ID);
            }
        }

        public GetPublicKeyNostrKeyVaultCall(KeyPath path, GetPublicKeyNostrCallConfig config) {
            super(path, config);
        }

        @SneakyThrows
        @Override
        byte[] execute() {

            return dkf.generatePublicKey(0);
////
////            SecureRandom dsr = WalletHelper.getDeterministicSecureRandomFromSeed(this.seed);
////            NostrCredentials credentials = new NostrCredentials(dsr, new NostrMetaData());
////            byte[] privateKeyBytes = NostrUtil.bytesFromBigInteger(((ECPrivateKey) credentials.kp.getPrivate()).getS());
////            byte[] publicKeyBytes = Schnorr.genPubKey(privateKeyBytes);
////
////            System.out.println(NostrUtil.bytesToHex(publicKeyBytes));
//
//            return publicKeyBytes;
        }
    }

    class SignEventNostrKeyVaultCall extends NostrKeyVaultCall<SignEventNostrKeyVaultCall.SignEventNostrCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0002;

        static class SignEventNostrCallConfig extends AbstractNostrCallConfig {

            private final byte[] pubkey;
            private final byte[] hash;

            SignEventNostrCallConfig(byte[] pubkey, byte[] hash) {
                super(CALL_ID);
                this.pubkey = pubkey;
                this.hash = hash;
            }
        }

        public SignEventNostrKeyVaultCall(KeyPath path, SignEventNostrCallConfig config) {
            super(path, config);
        }

        @SneakyThrows
        @Override
        byte[] execute() {
            byte[] privateKeyBytes = dkf.generatePrivateKey(config.pubkey);
            byte[] randomByteArray = NostrUtil.createRandomByteArray(32);

            return Schnorr.sign(config.hash, privateKeyBytes, randomByteArray);
        }
    }

    abstract class AbstractNip44NostrKeyVaultCall<A extends AbstractNip44NostrKeyVaultCall.AbstractNip44NostrCallConfig>
            extends NostrKeyVaultCall<A> {
        protected final byte[] prvKey = dkf.generatePrivateKey(config.pubKey);

        public AbstractNip44NostrKeyVaultCall(KeyPath path, A config) {
            super(path, config);
        }

        abstract static class AbstractNip44NostrCallConfig extends AbstractNostrCallConfig {

            protected final byte[] pubKey;
            protected final byte[] counterPartPubkey;
            protected final byte[] message;

            AbstractNip44NostrCallConfig(int callId, byte[] pubKey, byte[] counterPartPubkey, byte[] message) {
                super(callId);
                this.pubKey = pubKey;
                this.counterPartPubkey = counterPartPubkey;
                this.message = message;
            }
        }
    }

    class Nip44EncryptNostrKeyVaultCall extends AbstractNip44NostrKeyVaultCall<Nip44EncryptNostrKeyVaultCall.Nip44EncryptNostrCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0005;

        static class Nip44EncryptNostrCallConfig extends AbstractNip44NostrKeyVaultCall.AbstractNip44NostrCallConfig {
            Nip44EncryptNostrCallConfig(byte[] pubKey, byte[] counterPartPubkey, byte[] message) {
                super(CALL_ID, pubKey, counterPartPubkey, message);
            }
        }

        public Nip44EncryptNostrKeyVaultCall(KeyPath path, Nip44EncryptNostrCallConfig config) {
            super(path, config);
        }

        @SneakyThrows
        @Override
        byte[] execute() {
            MessageCipher cipher = new MessageCipher44(prvKey, config.counterPartPubkey);
            return cipher.encrypt(new String(config.message)).getBytes();
        }
    }

    class Nip44DecryptNostrKeyVaultCall extends AbstractNip44NostrKeyVaultCall<Nip44DecryptNostrKeyVaultCall.Nip44DecryptNostrCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0006;

        static class Nip44DecryptNostrCallConfig extends AbstractNip44NostrKeyVaultCall.AbstractNip44NostrCallConfig  {

            Nip44DecryptNostrCallConfig(byte[] pubKey, byte[] receiverPubkey, byte[] message) {
                super(CALL_ID, pubKey, receiverPubkey, message);
            }
        }

        public Nip44DecryptNostrKeyVaultCall(KeyPath path, Nip44DecryptNostrCallConfig config) {
            super(path, config);
        }

        @SneakyThrows
        @Override
        byte[] execute() {
            MessageCipher cipher = new MessageCipher44(prvKey, config.counterPartPubkey);
            return cipher.decrypt(new String(config.message)).getBytes();
        }
    }

    abstract class AbstractBitcoinKeyVaultCall<A extends AbstractBitcoinKeyVaultCall.AbstractBitcoinCallConfig> extends AbstractKeyVaultCall<A> {
        static int CALL_ID_OFFSET = 0x5000;

        abstract static class AbstractBitcoinCallConfig extends AbstractCallConfig {
            final Network network;
            final ScriptType scriptType;

            AbstractBitcoinCallConfig(int callId, Network network, ScriptType scriptType) {
                super(callId);
                this.network = network;
                this.scriptType = scriptType;
            }
        }

        final DeterministicKeyChain keyChain;

        public AbstractBitcoinKeyVaultCall(KeyPath path, A config) {
            super(path, config);
            this.keyChain = createKeyChain(config.network, seed, config.scriptType);
        }
    }

    public class SignBitcoinKeyVaultCall extends AbstractBitcoinKeyVaultCall<SignBitcoinKeyVaultCall.SignBitcoinCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0002;

        public static class SignBitcoinCallConfig extends AbstractBitcoinCallConfig {
            private final byte[] hash;
            private final byte[] pubKeyHash;

            public SignBitcoinCallConfig(Network network, ScriptType scriptType, byte[] hash, byte[] pubKeyHash) {
                super(CALL_ID, network, scriptType);
                this.hash = hash;
                this.pubKeyHash = pubKeyHash;
            }
        }

        final SignBitcoinCallConfig config;

        public SignBitcoinKeyVaultCall(KeyPath path, SignBitcoinCallConfig config) {
            super(path, config);
            this.config = config;
        }

        byte[] execute() {
            DeterministicKey keyFromPubHash = keyChain.findKeyFromPubHash(config.pubKeyHash);
            ECKey.ECDSASignature sign = keyFromPubHash.sign(Sha256Hash.wrap(config.hash));
            return sign.encodeToDER();
        }
    }

    class GetWatchingKeyBitcoinKeyVaultCall extends AbstractBitcoinKeyVaultCall<GetWatchingKeyBitcoinKeyVaultCall.GetWatchingKeyBitcoinCallConfig> {
        static int CALL_ID = CALL_ID_OFFSET + 0x0001;

        static class GetWatchingKeyBitcoinCallConfig extends AbstractBitcoinCallConfig {
            GetWatchingKeyBitcoinCallConfig(Network network, ScriptType scriptType) {
                super(CALL_ID, network, scriptType);
            }
        }

        public GetWatchingKeyBitcoinKeyVaultCall(KeyPath path, GetWatchingKeyBitcoinCallConfig config) {
            super(path, config);
        }

        @Override
        byte[] execute() {
            DeterministicKey key = keyChain
                    .getWatchingKey()
                    .dropParent()
                    .dropPrivateBytes();

            return key.serializePubB58(config.network).getBytes(StandardCharsets.UTF_8);
        }
    }

    //    private final Network network;
    private final DeterministicSeed seed;

    static DeterministicKeyChain createKeyChain(Network network, DeterministicSeed seed, ScriptType type) {
        KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;

        HDPath path = kcgs.accountPathFor(type, network);
        DeterministicKeyChain dkc = DeterministicKeyChain.builder()
                .seed(seed)
                .outputScriptType(type)
                .accountPath(path)
                .build();

        dkc.setLookaheadSize(100);
        dkc.maybeLookAhead();

        return dkc;
    }

    public KeyVault(DeterministicSeed seed) {
//        this.network = network;
        this.seed = seed;
    }

    private DeterministicSeed generateSeed(KeyPath path) {
        DeterministicSeed idSeed = WalletHelper.createSubSeed(this.seed, path.identity, "");
        DeterministicSeed protocolSeed = WalletHelper.createSubSeed(idSeed, path.protocol, "");
        return WalletHelper.createSubSeed(protocolSeed, path.config, "");
    }

    static Map<Integer, Class<? extends AbstractKeyVaultCall>> callMap = new HashMap<>();

    static {
        callMap.put(SignBitcoinKeyVaultCall.CALL_ID, SignBitcoinKeyVaultCall.class);
        callMap.put(GetWatchingKeyBitcoinKeyVaultCall.CALL_ID, GetWatchingKeyBitcoinKeyVaultCall.class);

        callMap.put(GetPublicKeyNostrKeyVaultCall.CALL_ID, GetPublicKeyNostrKeyVaultCall.class);
        callMap.put(SignEventNostrKeyVaultCall.CALL_ID, SignEventNostrKeyVaultCall.class);
        callMap.put(Nip44EncryptNostrKeyVaultCall.CALL_ID, Nip44EncryptNostrKeyVaultCall.class);
        callMap.put(Nip44DecryptNostrKeyVaultCall.CALL_ID, Nip44DecryptNostrKeyVaultCall.class);
    }

    @SneakyThrows
    public byte[] execute(KeyPath keyPath, AbstractKeyVaultCall.AbstractCallConfig callConfig) {
        AbstractKeyVaultCall<?> callExecutor = callMap.get(callConfig.callId)
                .getDeclaredConstructor(KeyVault.class, KeyPath.class, callConfig.getClass())
                .newInstance(this, keyPath, callConfig);

        return callExecutor.execute();
    }
}
