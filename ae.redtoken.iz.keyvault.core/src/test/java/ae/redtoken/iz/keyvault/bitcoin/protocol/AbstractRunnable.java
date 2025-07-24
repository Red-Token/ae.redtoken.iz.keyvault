package ae.redtoken.iz.keyvault.bitcoin.protocol;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

abstract class AbstractRunnable implements Runnable {
    BlockingQueue<TestMessageBus.Request> work = new ArrayBlockingQueue<>(100);
    Map<Integer, TestMessageBus.Transaction> transactions = new HashMap<>();
    int reqCount = 0;

    void onRequest(TestMessageBus.Request request) {
        work.add(request);
    }

    void onResponse(int id, TestMessageBus.Response response) {
        transactions.get(id).response.add(response);
    }
}
