package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import ae.redtoken.iz.keyvault.bitcoin.ConfigurationHelper;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolStackedService;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import nostr.event.impl.GenericEvent;
import nostr.util.NostrUtil;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bouncycastle.math.ec.ECPoint;
import org.jetbrains.annotations.Nullable;

public class KeyVaultProxy {

    public class BitcoinProtocolExecutor {
        public final BitcoinConfiguration config;
        private final KeyVault.KeyPath keyPath;

        public BitcoinProtocolExecutor(BitcoinConfiguration config) {
            this.config = config;
            this.keyPath = new KeyVault.KeyPath(WalletHelper.mangle(
                    identity.id),
                    WalletHelper.mangle(BitcoinProtocolStackedService.PROTOCOL_ID),
                    WalletHelper.mangle(ConfigurationHelper.toJSON(config)));

        }

        public class WrapedEcKey extends ECKey {
            private final ScriptType scriptType;

            public WrapedEcKey(ECPoint pub, boolean compressed, ScriptType scriptType) {
                super(null, pub, compressed);
                this.scriptType = scriptType;
            }

            @Override
            public boolean hasPrivKey() {
                return true;
            }

            @SneakyThrows
            @Override
            public ECDSASignature sign(Sha256Hash input, @Nullable AesKey aesKey) throws KeyCrypterException {
                return BitcoinProtocolExecutor.this.sign(scriptType, input, getPubKeyHash());
            }
        }

        @SneakyThrows
        public ECKey.ECDSASignature sign(ScriptType scriptType, Sha256Hash input, byte[] pubKeyHash) {
            KeyVault.SignBitcoinKeyVaultCall.SignBitcoinCallConfig callConfig = new KeyVault.SignBitcoinKeyVaultCall.SignBitcoinCallConfig(
                    config.network(), scriptType, input.getBytes(), pubKeyHash);

            byte[] bytes = kvr.executeTask(keyPath, callConfig);
            return ECKey.ECDSASignature.decodeFromDER(bytes);
        }

        public String getWatchingKey() {
            KeyVault.GetWatchingKeyBitcoinKeyVaultCall.GetWatchingKeyBitcoinCallConfig callConfig
                    = new KeyVault.GetWatchingKeyBitcoinKeyVaultCall.GetWatchingKeyBitcoinCallConfig(
                    config.network(),
                    config.scriptTypes().stream().findFirst().orElseThrow());

            byte[] bytes = kvr.executeTask(keyPath, callConfig);
            return new String(bytes);
        }
    }

    public class NostrProtocolExecutor {
        public final NostrConfiguration config;
        private final KeyVault.KeyPath keyPath;

        public NostrProtocolExecutor(NostrConfiguration config) {
            this.config = config;
            this.keyPath = new KeyVault.KeyPath(WalletHelper.mangle(
                    identity.id),
                    WalletHelper.mangle(NostrProtocolStackedService.PROTOCOL_ID),
                    WalletHelper.mangle(ConfigurationHelper.toJSON(config)));
        }

        public String getPublicKey() {
            KeyVault.GetPublicKeyNostrKeyVaultCall.GetPublicKeyNostrCallConfig callConfig
                    = new KeyVault.GetPublicKeyNostrKeyVaultCall.GetPublicKeyNostrCallConfig();

            byte[] bytes = kvr.executeTask(keyPath, callConfig);

            return NostrUtil.bytesToHex(bytes);
        }

        @SneakyThrows
        public String signEvent(String event) {
            ObjectMapper om = new ObjectMapper();
            GenericEvent ge = om.readValue(event, GenericEvent.class);

            // To KV we send
            byte[] pubkey = ge.getPubKey().getRawData();
            byte[] sha256 = NostrUtil.hexToBytes(ge.getId());

            KeyVault.SignEventNostrKeyVaultCall.SignEventNostrCallConfig callConfig = new KeyVault.SignEventNostrKeyVaultCall.SignEventNostrCallConfig(pubkey, sha256);
            byte[] bytes = kvr.executeTask(keyPath, callConfig);

            return NostrUtil.bytesToHex(bytes);
        }

        public String nip44Encrypt(String pubKey, String conPubKey, String message) {
            KeyVault.Nip44EncryptNostrKeyVaultCall.Nip44EncryptNostrCallConfig callConfig = new KeyVault.Nip44EncryptNostrKeyVaultCall.Nip44EncryptNostrCallConfig(
                    NostrUtil.hexToBytes(pubKey),
                    NostrUtil.hexToBytes(conPubKey),
                    message.getBytes());
            byte[] bytes = kvr.executeTask(keyPath, callConfig);
            return new String(bytes);
        }

        public String nip44Decrypt(String pubKey, String conPubKey, String encryptedMessage) {
            KeyVault.Nip44DecryptNostrKeyVaultCall.Nip44DecryptNostrCallConfig callConfig = new KeyVault.Nip44DecryptNostrKeyVaultCall.Nip44DecryptNostrCallConfig(
                    NostrUtil.hexToBytes(pubKey),
                    NostrUtil.hexToBytes(conPubKey),
                    encryptedMessage.getBytes());
            byte[] bytes = kvr.executeTask(keyPath, callConfig);
            return new String(bytes);
        }

    }

    private final IdentityStackedService identity;
    private final KeyVaultRunnable kvr;

    public KeyVaultProxy(IdentityStackedService identity, KeyVaultRunnable kvr) {
        this.identity = identity;
        this.kvr = kvr;
    }
}
