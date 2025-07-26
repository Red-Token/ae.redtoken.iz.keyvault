package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedSubService;

import java.util.HashMap;
import java.util.Map;

public class IdentityStackedService extends StackedSubService<KeyMasterStackedService> implements IIdentity {
    static Map<String, Class<? extends AbstractProtocolStackedService>> protocolFactory = new HashMap<>();

    static {
        protocolFactory.put(BitcoinProtocolStackedService.PROTOCOL_ID, BitcoinProtocolStackedService.class);
    }

    public final String id;
    public final KeyVaultProxy proxy;

    public IdentityStackedService(KeyMasterStackedService km, String id) {
        super(km, id);
        this.id = id;
        this.proxy = new KeyVaultProxy(this, km.keyVault);
    }
}
