package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MasterRunnable<A extends StackedService>  {
//public class MasterRunnable<A extends StackedService> extends AbstractRunnable implements Runnable {

    public final A rootStackedService;
    public ExecutorService executor = Executors.newCachedThreadPool();

//    public BlockingQueue<Request> work = new ArrayBlockingQueue<>(100);

//    public static class DirectRequestReceiver<A extends StackedService> {
//        protected final static ObjectMapper mapper = new ObjectMapper();
//
//        final MasterRunnable<A> masterRunnable;
//
//        public DirectRequestReceiver(MasterRunnable<A> masterRunnable) {
//            this.masterRunnable = masterRunnable;
//        }
//
//        @SneakyThrows
//        public void receiveRequest(byte[] request) {
//            masterRunnable.onRequest(mapper.readValue(request, Request.class));
//        }
//    }

    public static class DirectResponseSender<A extends StackedService> {
        public final static ObjectMapper mapper = new ObjectMapper();

        AvatarConnector.DirectResponseReceiver<A> target;

        @SneakyThrows
        public void sendResponse(Response response) {
            target.receiveResponse(mapper.writeValueAsBytes(response));
        }
    }

    public MasterRunnable(A rootStackedService) {
        this.rootStackedService = rootStackedService;
    }

//    void onRequest(Request request) {
////        work.add(request);
//    }


    public interface IResponseSender {
        void sendResponse(Response response);
    }

    public class RequestTask implements Runnable {
        final Request request;
        private final IResponseSender sender;

        public RequestTask(Request request, IResponseSender sender) {
            this.request = request;
            this.sender = sender;
        }

        @Override
        public void run() {
            Response r = new Response(request.id(), rootStackedService.process(new ArrayList<>(List.of(request.address())), request.message()));
            sender.sendResponse(r);
        }
    }

//    @SneakyThrows
//    @Override
//    public void run() {
//
////        while (run) {
////            executor.execute(new RequestTask(ws.receiveRequest(), new IResponseSender() {
////                @Override
////                public void sendResponse(Response response) {
////                    ws.sendResponse(response);
////                }
////            }));
////        }
////
////        executor.close();
//    }
}
