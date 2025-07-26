package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

abstract public class StackedService implements IStackedService {
    final public StackedService parent;
    final public Map<String, StackedService> subServices = new HashMap<>();

    final ServiceProcessor<?> processor;

    public StackedService(StackedService parent, String id) {
        this.parent = parent;
        this.processor = new ServiceProcessor<>(this);

        if(parent != null) {
            parent.subServices.put(id, this);
        }
    }

    Response process(List<String> address, String message) {
        if (address.isEmpty()) {
            String process = processor.process(message);
            return new Response(process);
        }

        return subServices.get(address.removeFirst()).process(address, message);
    }

//    public String getId() {
//        return new String(WalletHelper.mangle(getIdString()));
//    }


    @Override
    public String getDefaultId() {
        return this.subServices.keySet().iterator().next();
    }

    @Override
    public Set<String> getChildIds() {
        return this.subServices.keySet();
    }

//    protected abstract String getIdString();
}
