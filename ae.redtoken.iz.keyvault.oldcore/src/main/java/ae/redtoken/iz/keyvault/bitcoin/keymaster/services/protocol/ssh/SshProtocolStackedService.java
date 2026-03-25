package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;

public class SshProtocolStackedService extends AbstractProtocolStackedService {
    public static String PROTOCOL_ID = "ssh";

    public SshProtocolStackedService(IdentityStackedService parent) {
        super(parent, PROTOCOL_ID);
    }

    @Override
    public Class<? extends AbstractConfigurationStackedService> getConfigurationStackedServiceClass() {
        return SshConfigurationStackedService.class;
    }
}
