package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultRunnable;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

public class KeyMasterStackedService extends StackedService implements IKeyMaster {
    public final KeyVaultRunnable kvr;
    public final Thread kvrThread;
//    public final KeyVault keyVault;

    public KeyMasterStackedService(KeyVault keyVault) {
//        this.keyVault = keyVault;
        this.kvr = new KeyVaultRunnable(keyVault);
        this.kvrThread = new Thread(kvr);
        kvrThread.start();

    }
}
