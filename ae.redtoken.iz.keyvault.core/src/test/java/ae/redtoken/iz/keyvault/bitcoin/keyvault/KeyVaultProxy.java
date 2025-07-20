package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.*;
import org.bouncycastle.math.ec.ECPoint;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyVaultProxy {
    private static final Logger log = LoggerFactory.getLogger(KeyVaultProxy.class);

    public class BitcoinProtocolExecutor {
        public final TestWallet.BitcoinConfiguration config;

        public BitcoinProtocolExecutor(TestWallet.BitcoinConfiguration config) {
            this.config = config;
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
            KeyVault.KeyPath keyPath = new KeyVault.KeyPath(WalletHelper.mangle(
                    identity.id),
                    WalletHelper.mangle(TestWallet.BitcoinProtocol.protocolId),
                    WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config)));

            KeyVault.SignBitcoinKeyVaultCall.SignBitcoinCallConfig callConfig = new KeyVault.SignBitcoinKeyVaultCall.SignBitcoinCallConfig(
                    config.network(), scriptType, input.getBytes(), pubKeyHash);

            byte[] bytes = keyVault.execute(keyPath, callConfig);
            return ECKey.ECDSASignature.decodeFromDER(bytes);
        }

        public String getWatchingKey() {
            KeyVault.KeyPath keyPath = new KeyVault.KeyPath(WalletHelper.mangle(
                    identity.id),
                    WalletHelper.mangle(TestWallet.BitcoinProtocol.protocolId),
                    WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config)));

            KeyVault.GetWatchingKeyBitcoinKeyVaultCall.GetWatchingKeyBitcoinCallConfig callConfig
                    = new KeyVault.GetWatchingKeyBitcoinKeyVaultCall.GetWatchingKeyBitcoinCallConfig(
                    config.network(),
                    config.scriptTypes().stream().findFirst().orElseThrow());

            byte[] bytes = keyVault.execute(keyPath, callConfig);
            return new String(bytes);
        }
    }

    private final TestWallet.Identity identity;
    private final KeyVault keyVault;

    public KeyVaultProxy(TestWallet.Identity identity, KeyVault keyVault) {
        this.identity = identity;
        this.keyVault = keyVault;
    }
}
