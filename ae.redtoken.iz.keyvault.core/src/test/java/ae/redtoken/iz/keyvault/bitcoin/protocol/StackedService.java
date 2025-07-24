package ae.redtoken.iz.keyvault.bitcoin.protocol;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

class StackedService {
    Map<String, StackedService> subServices = new HashMap<>();

    final ServiceProcessor<?> processor;

    StackedService() {
        this.processor = new ServiceProcessor<>(this);
    }

    TestMessageBus.Response process(List<String> address, String message) {
        if (address.isEmpty()) {
            String process = processor.process(message);
            return new TestMessageBus.Response(process);
        }

        return subServices.get(address.removeFirst()).process(address, message);
    }

}
