package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class MasterRunnable<A extends StackedService> extends AbstractRunnable implements Runnable {
    public final A rootStackedService;
    BlockingQueue<Request> work = new ArrayBlockingQueue<>(100);
    public  DirectResponseSender<A> sender = new DirectResponseSender<>();
    public final DirectRequestReceiver<A> receiver = new DirectRequestReceiver<A>(this);

    public static class DirectRequestReceiver<A extends StackedService> {
        protected final static ObjectMapper mapper = new ObjectMapper();

        final MasterRunnable<A> masterRunnable;

        public DirectRequestReceiver(MasterRunnable<A> masterRunnable) {
            this.masterRunnable = masterRunnable;
        }

        @SneakyThrows
        public void receiveRequest(byte[] request) {
            masterRunnable.onRequest(mapper.readValue(request, Request.class));
        }
    }

    public static class DirectResponseSender<A extends StackedService>  {
        public final static ObjectMapper mapper = new ObjectMapper();
//        public InetSocketAddress address;
//        public DatagramSocket socket;

        Avatar.DirectResponseReceiver<A> target;

        @SneakyThrows
        public void sendResponse(Response response) {
            target.receiveResponse(mapper.writeValueAsBytes(response));
        }
    }

    public MasterRunnable(A rootStackedService) {
        this.rootStackedService = rootStackedService;
    }

    void onRequest(Request request) {
        work.add(request);
    }

    @SneakyThrows
    @Override
    public void run() {
        while (true) {
            Request request = work.take();
            Response r = new Response(request.id(), rootStackedService.process(new ArrayList<>(List.of(request.address())), request.message()));
            sender.sendResponse(r);
        }
    }
}
