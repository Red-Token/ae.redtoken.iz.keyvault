package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

public abstract class AbstractConfigurationStackedService extends StackedService {
    public AbstractConfigurationStackedService(AbstractProtocolStackedService parent, String id) {
        super(parent, id);
    }
}
