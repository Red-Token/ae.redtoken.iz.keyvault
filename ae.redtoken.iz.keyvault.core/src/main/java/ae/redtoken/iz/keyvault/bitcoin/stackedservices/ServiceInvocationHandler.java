package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.*;

public class ServiceInvocationHandler<A extends StackedService> implements InvocationHandler {
    static final ObjectMapper mapper = new ObjectMapper();

    int callCount = 0;
    final String[] address;
    final AvatarConnector<A> runnable;

    public ServiceInvocationHandler(String[] address, AvatarConnector<A> runnable) {
        this.address = address;
        this.runnable = runnable;
    }

    record CallRequestMessage(long id, String methodName, Object[] args) {
    }

    record CallResponseMessage(long id, Object result) {
    }

    static Method findMethod(Class<?> cls, CallRequestMessage callObject) {
        return Arrays.stream(cls.getMethods())
                .filter(m -> m.getName().equals(callObject.methodName()))
                .findFirst()
                .orElseThrow();
    }

    @SneakyThrows
    static Object recast(Object parameter, Class<?> type) {
        return mapper.readValue(mapper.writeValueAsString(parameter), type);
    }

    String send(String[] address, String message) {
        return runnable.sendText(address, message);
    }

    @Override
    public Object invoke(Object caller, Method method, Object[] objects) throws Throwable {
        final int callId = callCount++;
        String requestMessage = mapper.writeValueAsString(new CallRequestMessage(callId, method.getName(), objects));
        String responseMessage = send(address, requestMessage);
        CallResponseMessage rep = mapper.readValue(responseMessage, CallResponseMessage.class);
        return recast(rep.result, method.getReturnType());
    }
}
