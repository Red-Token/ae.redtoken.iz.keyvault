package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.MasterRunnable;

public class KeyMasterExecutor extends MasterRunnable<KeyMasterStackedService> {

    public KeyMasterExecutor(KeyMasterStackedService rootStackedService) {
        super(rootStackedService);
    }
}
