package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class StackedService {
    public Map<String, StackedService> subServices = new HashMap<>();

    final ServiceProcessor<?> processor;

    public StackedService() {
        this.processor = new ServiceProcessor<>(this);
    }

    Response process(List<String> address, String message) {
        if (address.isEmpty()) {
            String process = processor.process(message);
            return new Response(process);
        }

        return subServices.get(address.removeFirst()).process(address, message);
    }

}
