package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.List;

public class MasterRunnable<A extends StackedService> extends AbstractRunnable {
    public final A rootStackedService;

    public MasterRunnable(A rootStackedService) {
        this.rootStackedService = rootStackedService;
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
