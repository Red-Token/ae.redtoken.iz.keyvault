package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.util.WalletHelper;

public class BitcoinConfigurationStackedService extends AbstractConfigurationStackedService implements IBitcoinConfiguration {
    public final BitcoinConfiguration config;
    public final BitcoinMasterService bms;

    public BitcoinConfigurationStackedService(BitcoinProtocolStackedService parent, BitcoinConfiguration config) {
        super(parent, new String(WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config))));
        this.config = config;
        bms = new BitcoinMasterService(parent.parent.proxy.new BitcoinProtocolExecutor(config), config);
    }

    @Override
    public BitcoinProtocolMessages.GetWatchingKeyAccept getWatchingKey() {
        return bms.getWatchingKey();
    }

    @Override
    public BitcoinProtocolMessages.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request) {
        return bms.signTransaction(request);
    }

//    @Override
//    protected String getIdString() {
//        return TestWallet.ConfigurationHelper.toJSON(config);
//    }
}
