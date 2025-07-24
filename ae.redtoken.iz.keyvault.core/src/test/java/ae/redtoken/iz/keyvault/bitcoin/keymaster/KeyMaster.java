package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.protocol.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.protocol.Identity;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class KeyMaster extends StackedService {
    final Collection<Identity> identities = new ArrayList<>();
    final KeyVault keyVault;

    public Map<String, BitcoinMasterService> bmsm = new HashMap<>();

    public KeyMaster(KeyVault keyVault) {
        this.keyVault = keyVault;
    }

    public Collection<Identity> getIdentities() {
        return identities;
    }
    public Identity getDefaultIdentity() {
        return identities.iterator().next();
    }

    public void createBitcoinMasterService(Identity id, BitcoinConfiguration config) {
        // Retrieve the WatchingKey to setup the wallet
        // TODO, this should be done from an ID
        KeyVaultProxy proxy = new KeyVaultProxy(id,keyVault);
        bmsm.put(id.id, new BitcoinMasterService(proxy, config));
    }

    // Process Request
    public Object processRequest() {
        return null;
    }
}
