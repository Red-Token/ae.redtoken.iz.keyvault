package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfigurationStackedService;

public class NostrProtocolStackedService extends AbstractProtocolStackedService {
    public static String PROTOCOL_ID = "nostr";

    public NostrProtocolStackedService(IdentityStackedService parent) {
        super(parent, PROTOCOL_ID);
    }

    @Override
    public Class<? extends AbstractConfigurationStackedService> getConfigurationStackedServiceClass() {
        return NostrConfigurationStackedService.class;
    }
}
