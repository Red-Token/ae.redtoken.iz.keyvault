package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

public class KeyMasterStackedService extends StackedService implements IKeyMaster {
    public final KeyVault keyVault;

    public KeyMasterStackedService(KeyVault keyVault) {
        this.keyVault = keyVault;
    }
}
