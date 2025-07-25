package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.util.WalletHelper;

public class BitcoinConfigurationStackedService extends AbstractConfigurationStackedService {
    public final BitcoinConfiguration config;

    public BitcoinConfigurationStackedService(AbstractProtocolStackedService parent, BitcoinConfiguration config) {
        super(parent, new String(WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(config))));
        this.config = config;
    }

//    @Override
//    protected String getIdString() {
//        return TestWallet.ConfigurationHelper.toJSON(config);
//    }
}
