package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.util.WalletHelper;

public class BitcoinConfigurationStackedService extends AbstractConfigurationStackedService implements IBitcoinConfiguration {
    public final BitcoinConfiguration config;
    public final BitcoinMasterService bms;

    public BitcoinConfigurationStackedService(BitcoinProtocolStackedService parent, BitcoinConfiguration config) {
        super(parent, new String(WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config))));
        this.config = config;
        KeyMasterStackedService kmss = (KeyMasterStackedService) parent.parent.parent;
        KeyVaultProxy proxy = new KeyVaultProxy((IdentityStackedService) parent.parent, kmss.keyVault);
        bms = new BitcoinMasterService(proxy.new BitcoinProtocolExecutor(config), config);
    }

    @Override
    public BitcoinProtocolM.GetWatchingKeyAccept getWatchingKey() {
        return bms.getWatchingKey();
    }

    @Override
    public BitcoinProtocolM.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolM.BitcoinTransactionSignatureRequest request) {
        return bms.signTransaction(request);
    }

//    @Override
//    protected String getIdString() {
//        return TestWallet.ConfigurationHelper.toJSON(config);
//    }
}
