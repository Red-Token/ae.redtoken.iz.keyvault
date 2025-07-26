package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.Set;

public interface IStackedService {
    String getDefaultId();
    Set<String> getChildIds();
}
