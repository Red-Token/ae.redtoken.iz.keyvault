package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Slf4j
public class ServiceProcessor<S> {
    static final ObjectMapper mapper = new ObjectMapper();
    final S service;

    ServiceProcessor(S service) {
        this.service = service;
    }

    @SneakyThrows
    public String process(String requestMessage) {
        log.atDebug().log("Processing request message: %s", requestMessage);


        // Receive the message
        ServiceInvocationHandler.CallRequestMessage callObject = mapper.readValue(requestMessage, ServiceInvocationHandler.CallRequestMessage.class);
        Method targetMethod = ServiceInvocationHandler.findMethod(service.getClass(), callObject);
        List<Object> args = new ArrayList<>();

        for (int j = 0; j < targetMethod.getParameterCount(); j++) {
            Class<?> targetParameterType = targetMethod.getParameterTypes()[j];
            args.add(ServiceInvocationHandler.recast(Objects.requireNonNull(callObject.args())[j], targetParameterType));
        }

        // Execute the request
        Object result = targetMethod.invoke(service, args.toArray());

        // Create the response message
        ServiceInvocationHandler.CallResponseMessage callResponse = new ServiceInvocationHandler.CallResponseMessage(callObject.id(), result);

        String r = mapper.writeValueAsString(callResponse);
        log.atDebug().log("Response: %s", r);
        // Send it out as a string
        return r;
    }

}
