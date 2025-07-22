package ae.redtoken.iz.keyvault.bitcoin.protocol;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.*;

public class KeyMasterInvocationHandler implements InvocationHandler {

    int i = 0;
    static final ObjectMapper mapper = new ObjectMapper();
//    ServiceProcessor serviceProcessor;

    TestMessageBus.KeyMasterRunnable keyMasterRunnable;

    record CallRequestMessage(long id, String methodName, Object[] args) {
    }

    record CallResponseMessage(long id, Object result) {
    }

    static class ServiceProcessor {
        static final ObjectMapper mapper = new ObjectMapper();
        TestMessageBus.KeyMasterAPI service;

        @SneakyThrows
        public String process(String requestMessage) {
            // Receive the message
            CallRequestMessage callObject = mapper.readValue(requestMessage, CallRequestMessage.class);
            Method targetMethod = findMethod(service.getClass(), callObject);
            List<Object> args = new ArrayList<>();

            for (int j = 0; j < targetMethod.getParameterCount(); j++) {
                Class<?> targetParameterType = targetMethod.getParameterTypes()[j];
                args.add(recast(Objects.requireNonNull(callObject.args)[j], targetParameterType));
            }

            // Execute the request
            Object result = targetMethod.invoke(service, args.toArray());

            // Create the response message
            System.out.println("XXX" + result.getClass());
            CallResponseMessage callResponse = new CallResponseMessage(callObject.id, result);

            String r = mapper.writeValueAsString(callResponse);
            // Send it out as a string
            return r;
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

    String send(String requestMessage) {
        return "NO!";
    }

    @Override
    public Object invoke(Object caller, Method method, Object[] objects) throws Throwable {
        final int callId = i++;
        String requestMessage = mapper.writeValueAsString(new CallRequestMessage(callId, method.getName(), objects));
        System.out.println(requestMessage);
        // Create Request

        String r = send(requestMessage);

        CallResponseMessage rep = mapper.readValue(r, CallResponseMessage.class);
        System.out.println(rep.result.getClass());

        // Make sure we have the right response
//        Class<?> returnType = method.getReturnType();
//
//        System.out.println(returnType);

//        if(!method.getReturnType().equals(rep.result.getClass())) {
//            // Magic mushroom!
//            returnType.isArray();
//
//            System.out.println(rep.result);
//            return convertToTypedArray((Collection<?>) rep.result, returnType);
//        }

        return recast(rep.result, method.getReturnType());
    }

//    public static <T> T convertToTypedArray(Collection<?> input, Class<?> arrayType) {
//        // Get the component type of the array, e.g., String.class from String[].class
//        Class<?> componentType = arrayType.getComponentType();
//
//        Object typedArray = Array.newInstance(componentType, input.size());
//        return (T) input.toArray((Object[]) typedArray);
//    }

    public static <T> T convertToTypedArray(Collection<?> input, Class<?> arrayType) {
        if (!arrayType.isArray()) {
            throw new IllegalArgumentException("Expected array type (e.g., String[].class or String[][].class)");
        }

        Class<?> componentType = arrayType.getComponentType();
        Object array = Array.newInstance(componentType, input.size());

        int i = 0;
        for (Object item : input) {
            // Defensive: check if each element is assignable
            if (!componentType.isInstance(item)) {
                throw new ArrayStoreException(
                        "Cannot store element of type " + item.getClass() + " in array of " + componentType
                );
            }
            Array.set(array, i++, item);
        }

        return (T) array;
    }
}
