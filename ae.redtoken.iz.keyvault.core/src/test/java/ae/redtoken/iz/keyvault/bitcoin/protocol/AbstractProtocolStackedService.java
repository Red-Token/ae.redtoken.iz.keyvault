package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;

public abstract class AbstractProtocolStackedService extends StackedService {
    public AbstractProtocolStackedService(IdentityStackedService parent, String id) {
        super(parent, id);
    }
}
