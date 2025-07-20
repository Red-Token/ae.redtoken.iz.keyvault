package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.wallet.*;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class KeyVault {

    public record KeyPath(byte[] identity, byte[] protocol, byte[] config) {
    }

    public abstract class AbstractKeyVaultCall {
        public abstract static class AbstractCallConfig {
            final int callId;

            AbstractCallConfig(int callId) {
                this.callId = callId;
            }
        }

        protected final DeterministicSeed seed;

        public AbstractKeyVaultCall(KeyPath path) {
            this.seed = generateSeed(path);
        }

        abstract byte[] execute();
    }

    abstract class BitcoinKeyVaultCall extends AbstractKeyVaultCall {
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

        public BitcoinKeyVaultCall(KeyPath path, AbstractBitcoinCallConfig config) {
            super(path);
            this.keyChain = createKeyChain(config.network, seed, config.scriptType);
        }
    }

    public class SignBitcoinKeyVaultCall extends BitcoinKeyVaultCall {
        static int CALL_ID = CALL_ID_OFFSET + 0x0001;

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

    class GetWatchingKeyBitcoinKeyVaultCall extends BitcoinKeyVaultCall {
        static int CALL_ID = CALL_ID_OFFSET + 0x0002;

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

            return key.serializePubB58(network).getBytes(StandardCharsets.UTF_8);
        }
    }

    private final Network network;
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

    public KeyVault(Network network, DeterministicSeed seed) {
        this.network = network;
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
    }

    @SneakyThrows
    public byte[] execute(KeyPath keyPath, AbstractKeyVaultCall.AbstractCallConfig callConfig) {
        AbstractKeyVaultCall callExecutor = callMap.get(callConfig.callId)
                .getDeclaredConstructor(KeyVault.class, KeyPath.class, callConfig.getClass())
                .newInstance(this, keyPath, callConfig);

        return callExecutor.execute();
    }
}
