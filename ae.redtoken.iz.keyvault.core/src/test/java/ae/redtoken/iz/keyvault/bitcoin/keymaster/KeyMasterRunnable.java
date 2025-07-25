package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.MasterRunnable;

public class KeyMasterRunnable extends MasterRunnable<KeyMasterStackedService> {

    public KeyMasterRunnable(KeyMasterStackedService rootStackedService) {
        super(rootStackedService);
    }
}
