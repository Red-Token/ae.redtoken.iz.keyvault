package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class Transaction {
    final Request request;
    final BlockingQueue<Response> response = new ArrayBlockingQueue<>(1);

    public Transaction(Request request) {
        this.request = request;
    }
}
