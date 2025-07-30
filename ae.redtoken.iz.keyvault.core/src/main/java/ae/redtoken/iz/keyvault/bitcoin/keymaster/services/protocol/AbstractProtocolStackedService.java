package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedSubService;

public abstract class AbstractProtocolStackedService extends StackedSubService<IdentityStackedService> {
    public AbstractProtocolStackedService(IdentityStackedService parent, String id) {
        super(parent, id);
    }
}
