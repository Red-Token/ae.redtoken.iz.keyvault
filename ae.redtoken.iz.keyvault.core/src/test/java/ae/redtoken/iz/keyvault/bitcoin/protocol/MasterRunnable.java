package ae.redtoken.iz.keyvault.bitcoin.protocol;

import lombok.SneakyThrows;

import java.util.ArrayList;
import java.util.List;

public class MasterRunnable<A extends StackedService> extends AbstractRunnable {
    final A ss;

    public MasterRunnable(A ss) {
        this.ss = ss;
    }

    @SneakyThrows
    @Override
    public void run() {
        while (true) {
            TestMessageBus.Request request = work.take();
            TestMessageBus.Response r = ss.process(new ArrayList<>(List.of(request.address())), request.message());
            request.sender().onResponse(request.id(), r);
        }
    }
}
