package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.test.TestMessageBus;
import lombok.SneakyThrows;

import java.lang.reflect.Proxy;

abstract public class AvatarRunnable<T extends StackedService> extends AbstractRunnable {
    public MasterRunnable<T> masterRunnable;

    protected <A> A createProxy(String[] address, Class<A> cls) {
        ServiceInvocationHandler<T> handler = new ServiceInvocationHandler<>(address, this);
        return (A) Proxy.newProxyInstance(TestMessageBus.class.getClassLoader(), new Class[]{cls}, handler);
    }

    @SneakyThrows
    String sendText(String[] address, String message) {
        Request request = new Request(this, reqCount++, address, message);
        Transaction transaction = new Transaction(request);
        transactions.put(request.id(), transaction);
        masterRunnable.onRequest(request);
        Response response = transaction.response.take();
        return response.resp();
    }
}
