package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class StackedService implements IStackedService {

    final public Map<String, StackedSubService> subServices = new HashMap<>();

    final ServiceProcessor<?> processor;

    public StackedService() {
        this.processor = new ServiceProcessor<>(this);
    }

    String process(List<String> address, String message) {
        if (address.isEmpty()) {
            return processor.process(message);
        }

        return subServices.get(address.removeFirst()).process(address, message);
    }


    @Override
    public String getDefaultId() {
        return this.subServices.keySet().iterator().next();
    }

    @Override
    public Set<String> getChildIds() {
        return this.subServices.keySet();
    }


}
