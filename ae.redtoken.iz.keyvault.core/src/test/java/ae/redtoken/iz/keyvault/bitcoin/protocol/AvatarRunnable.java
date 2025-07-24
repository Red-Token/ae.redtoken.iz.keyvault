package ae.redtoken.iz.keyvault.bitcoin.protocol;

import lombok.SneakyThrows;

import java.lang.reflect.Proxy;

abstract public class AvatarRunnable<T extends StackedService> extends AbstractRunnable {
    MasterRunnable<T> masterRunnable;

    <A> A createProxy(String[] address, Class<A> cls) {
        ServiceInvocationHandler<T> handler = new ServiceInvocationHandler<>(address, this);
        return (A) Proxy.newProxyInstance(TestMessageBus.class.getClassLoader(), new Class[]{cls}, handler);
    }

    @SneakyThrows
    String sendText(String[] address, String message) {
        TestMessageBus.Request request = new TestMessageBus.Request(this, reqCount++, address, message);
        TestMessageBus.Transaction transaction = new TestMessageBus.Transaction(request);
        transactions.put(request.id(), transaction);
        masterRunnable.onRequest(request);
        TestMessageBus.Response response = transaction.response.take();
        return response.resp();
    }
}
