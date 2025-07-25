package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.BitcoinMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.util.WalletHelper;

public class BitcoinConfigurationStackedService extends AbstractConfigurationStackedService implements IBitcoinConfigurationStackedService  {
    public final BitcoinConfiguration config;
    public final BitcoinMasterService bms;

    public BitcoinConfigurationStackedService(BitcoinProtocolStackedService parent, BitcoinConfiguration config) {
        super(parent, new String(WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config))));
        this.config = config;
        KeyMasterStackedService kmss = (KeyMasterStackedService) parent.parent.parent;
        KeyVaultProxy proxy = new KeyVaultProxy((IdentityStackedService) parent.parent, kmss.keyVault);
        bms = new BitcoinMasterService(proxy, config);
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
