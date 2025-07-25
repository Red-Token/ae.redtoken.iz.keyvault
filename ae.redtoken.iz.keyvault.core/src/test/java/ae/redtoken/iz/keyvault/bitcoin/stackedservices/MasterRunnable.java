package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class MasterRunnable<A extends StackedService> extends AbstractRunnable implements Runnable {
    public final A rootStackedService;
    BlockingQueue<Request> work = new ArrayBlockingQueue<>(100);

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
            Response r = rootStackedService.process(new ArrayList<>(List.of(request.address())), request.message());
            request.sender().onResponse(request.id(), r);
        }
    }
}
