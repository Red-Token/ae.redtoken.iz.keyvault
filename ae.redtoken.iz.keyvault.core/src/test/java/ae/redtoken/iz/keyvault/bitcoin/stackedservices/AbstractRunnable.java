package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

abstract class AbstractRunnable implements Runnable {
    BlockingQueue<Request> work = new ArrayBlockingQueue<>(100);
    Map<Integer, Transaction> transactions = new HashMap<>();
    int reqCount = 0;

    void onRequest(Request request) {
        work.add(request);
    }

    void onResponse(int id, Response response) {
        transactions.get(id).response.add(response);
    }
}
