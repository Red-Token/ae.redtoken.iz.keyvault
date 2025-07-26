package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
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
        public final BitcoinConfiguration config;
        private final KeyVault.KeyPath keyPath;

        public BitcoinProtocolExecutor(BitcoinConfiguration config) {
            this.config = config;
            this.keyPath = new KeyVault.KeyPath(WalletHelper.mangle(
                    identity.id),
                    WalletHelper.mangle(BitcoinProtocolStackedService.PROTOCOL_ID),
                    WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config)));

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

    private final IdentityStackedService identity;
//    private final KeyVault keyVault;
    private final KeyVaultRunnable kvr;
//    public final Thread kvrThread;

    public KeyVaultProxy(IdentityStackedService identity, KeyVaultRunnable kvr) {
        this.identity = identity;
        this.kvr = kvr;
//        this.keyVault = keyVault;
    }
}
