package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedSubService;

public abstract class AbstractConfigurationStackedService extends StackedSubService<AbstractProtocolStackedService> {
    public AbstractConfigurationStackedService(AbstractProtocolStackedService parent, String id) {
        super(parent, id);
    }
}
