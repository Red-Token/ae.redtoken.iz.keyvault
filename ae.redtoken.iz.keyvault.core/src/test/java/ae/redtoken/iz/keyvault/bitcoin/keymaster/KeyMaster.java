package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class KeyMaster {
    final Collection<TestWallet.Identity> identities = new ArrayList<>();
    final KeyVault keyVault;

    public Map<String, BitcoinMasterService> bmsm = new HashMap<>();

    public KeyMaster(KeyVault keyVault) {
        this.keyVault = keyVault;
    }

    public Collection<TestWallet.Identity> getIdentities() {
        return identities;
    }
    public TestWallet.Identity getDefaultIdentity() {
        return identities.iterator().next();
    }

    public void createBitcoinMasterService(TestWallet.Identity id, TestWallet.BitcoinConfiguration config) {
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
