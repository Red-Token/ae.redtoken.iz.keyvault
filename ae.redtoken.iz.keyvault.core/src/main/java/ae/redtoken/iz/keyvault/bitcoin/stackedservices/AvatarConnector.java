package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.lang.reflect.Proxy;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AvatarConnector<T extends StackedService> {
    Map<Integer, Transaction> transactions = new HashMap<>();
    int reqCount = 0;

    public interface IRequestSender {
        void sendRequest(Request request);
    }

    protected IRequestSender sender;

//    public DirectRequestSender<T> sender;
//    public DirectResponseReceiver<T> receiver;

    public AvatarConnector(DatagramSocket socket, DatagramPacket packet) {
        System.out.println("Avatar");
    }

    public AvatarConnector() {
    }

    public AvatarConnector(MasterRunnable<T> masterRunnable) {
//        this.sender = new DirectRequestSender<>(masterRunnable.receiver);
//        this.receiver = new DirectResponseReceiver<>(this);
//        masterRunnable.sender.target = this.receiver;
    }

    public void onResponse(Response response) {
        transactions.get(response.id()).response.add(response);
    }

    protected <A> A createProxy(List<String> address, Class<A> cls) {
        return createProxy(address.toArray(new String[0]), cls);
    }

    protected <A> A createProxy(String[] address, Class<A> cls) {
        ServiceInvocationHandler<T> handler = new ServiceInvocationHandler<>(address, this);
        return (A) Proxy.newProxyInstance(AvatarConnector.class.getClassLoader(), new Class[]{cls}, handler);
    }

    interface  RequestSender {
        void sendRequest(Request request);
    }

//    public static class DirectRequestSender<T extends StackedService> implements RequestSender {
//        protected final static ObjectMapper mapper = new ObjectMapper();
//
//        final public MasterRunnable.DirectRequestReceiver<T> target;
//
//        public DirectRequestSender(MasterRunnable.DirectRequestReceiver<T> target) {
//            this.target = target;
//        }
//
//        @SneakyThrows
//        public void sendRequest(Request request) {
//            target.receiveRequest(mapper.writeValueAsBytes(request));
//        }
//    }

    // TODO Merge this with the Response reciver
    public static class DirectResponseReceiver<T extends StackedService> {
        final static ObjectMapper mapper = new ObjectMapper();

        final AvatarConnector<T> avatarConnector;

        public DirectResponseReceiver(AvatarConnector<T> avatarConnector) {
            this.avatarConnector = avatarConnector;
        }

        @SneakyThrows
        public void receiveResponse(byte[] response) {
            avatarConnector.onResponse(mapper.readValue(response, Response.class));
        }
    }

    @SneakyThrows
    String sendText(String[] address, String message) {
        Request request = new Request(reqCount++, address, message);
        Transaction transaction = new Transaction(request);
        transactions.put(request.id(), transaction);

        // Send it over the wire
        sender.sendRequest(request);

        // Receive it
        Response response = transaction.response.take();
        return response.resp();
    }
}
