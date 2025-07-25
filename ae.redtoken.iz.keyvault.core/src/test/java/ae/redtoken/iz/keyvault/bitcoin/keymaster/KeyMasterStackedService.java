package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.protocol.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.protocol.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

import java.util.HashMap;
import java.util.Map;

public class KeyMasterStackedService extends StackedService implements IKeyMaster {
//    final Collection<Identity> identities = new ArrayList<>();
    public final KeyVault keyVault;

    public Map<String, BitcoinMasterService> bmsm = new HashMap<>();

    public KeyMasterStackedService(KeyVault keyVault) {
        super(null, null);
        this.keyVault = keyVault;
    }

//    public Collection<Identity> getIdentities() {
//        return identities;
//    }
//
//    public Identity getDefaultIdentity() {
//        return identities.iterator().next();
//    }

    public void createBitcoinMasterService(IdentityStackedService id, BitcoinConfiguration config) {
        // Retrieve the WatchingKey to setup the wallet
        // TODO, this should be done from an ID
        KeyVaultProxy proxy = new KeyVaultProxy(id, keyVault);
        BitcoinMasterService bms = new BitcoinMasterService(proxy, config);
        bmsm.put(id.id, bms);
    }

    // Process Request
    public Object processRequest() {
        return null;
    }

//    @Override
//    protected String getIdString() {
//        return null;
//    }

    @Override
    public String getDefaultId() {
        return getChildIds().iterator().next();
    }
}
