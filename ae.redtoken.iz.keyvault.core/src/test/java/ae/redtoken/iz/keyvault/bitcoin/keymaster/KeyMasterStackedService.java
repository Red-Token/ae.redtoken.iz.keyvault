package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedSubService;

import java.util.HashMap;
import java.util.Map;

public class KeyMasterStackedService extends StackedService implements IKeyMaster {
//    final Collection<Identity> identities = new ArrayList<>();
    public final KeyVault keyVault;

    public Map<String, BitcoinMasterService> bmsm = new HashMap<>();

    public KeyMasterStackedService(KeyVault keyVault) {
        this.keyVault = keyVault;
    }


    // Process Request
    public Object processRequest() {
        return null;
    }


    @Override
    public String getDefaultId() {
        return getChildIds().iterator().next();
    }
}
