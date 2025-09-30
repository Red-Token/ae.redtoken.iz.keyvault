package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.*;

@Slf4j
public class ServiceInvocationHandler<A extends StackedService> implements InvocationHandler {
    static final ObjectMapper mapper = new ObjectMapper();

    int callCount = 0;
    final String[] address;
    final AvatarConnector<A> runnable;

    public ServiceInvocationHandler(String[] address, AvatarConnector<A> runnable) {
        this.address = address;
        this.runnable = runnable;
    }

    static final class CallRequestMessage {
        public long id;
        public String methodName;
        public Object[] args;

        CallRequestMessage(long id, String methodName, Object[] args) {
            this.id = id;
            this.methodName = methodName;
            this.args = args;
        }

        public CallRequestMessage() {
        }

        public long id() {
            return id;
        }

        public String methodName() {
            return methodName;
        }

        public Object[] args() {
            return args;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (CallRequestMessage) obj;
            return this.id == that.id &&
                    Objects.equals(this.methodName, that.methodName) &&
                    Objects.equals(this.args, that.args);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, methodName, args);
        }

        @Override
        public String toString() {
            return "CallRequestMessage[" +
                    "id=" + id + ", " +
                    "methodName=" + methodName + ", " +
                    "args=" + args + ']';
        }

        }

    static final class CallResponseMessage {
        public long id;
        public Object result;

        CallResponseMessage(long id, Object result) {
            this.id = id;
            this.result = result;
        }

        public CallResponseMessage() {
        }

        public long id() {
            return id;
        }

        public Object result() {
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (CallResponseMessage) obj;
            return this.id == that.id &&
                    Objects.equals(this.result, that.result);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, result);
        }

        @Override
        public String toString() {
            return "CallResponseMessage[" +
                    "id=" + id + ", " +
                    "result=" + result + ']';
        }

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

        log.atInfo().log(requestMessage);

        String responseMessage = send(address, requestMessage);
        CallResponseMessage rep = mapper.readValue(responseMessage, CallResponseMessage.class);
        return recast(rep.result, method.getReturnType());
    }
}
