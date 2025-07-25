package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.protocol.IdentityStackedService;

public interface IKeyMaster extends IStackedService {
    String getDefaultId();
}
