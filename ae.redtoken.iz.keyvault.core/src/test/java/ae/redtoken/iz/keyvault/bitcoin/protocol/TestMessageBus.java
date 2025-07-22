package ae.redtoken.iz.keyvault.bitcoin.protocol;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class TestMessageBus {

    class KeyMasterRequest {
    }

    class KeyMasterResponse {
    }

    interface KeyMasterAPI {
        String getDefaultId(String x, Integer y);

        //        Collection<List<String>> getIdentities(byte[] txt);
        String[][] getIdentities(byte[] txt);

    }

    static class KeyMasterService implements KeyMasterAPI {

        List<String> ids = new ArrayList<>();

        @Override
        public String getDefaultId(String x, Integer y) {
            return ids.getFirst();
        }

        @Override
        public String[][] getIdentities(byte[] txt) {
//        public Collection<List<String>> getIdentities(byte[] txt) {
            System.out.println(new String(txt));
            String[][] array = {{"sfdsdf", "sdfsdf"}, {"sdfsdf", "sdfsdf"}};
            return array;
//            return List.of(List.of("sfsdfsd", "sfsdfsdf"));
        }
    }


    static class Request {
        final int id;
        final String txt;
        final AbstractRunnable sender;

        Request(AbstractRunnable sender, int id, String txt) {
            this.id = id;
            this.txt = txt;
            this.sender = sender;
        }
    }

    static class Response {
        String resp;
    }

    static class Transaction {
        final Request request;
        final BlockingQueue<Response> response = new ArrayBlockingQueue<>(1);

        public Transaction(Request request) {
            this.request = request;
        }
    }

    static abstract class AbstractRunnable implements Runnable {
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

    static class KeyMasterRunnable extends AbstractRunnable {
        KeyMasterService service = new KeyMasterService();
        KeyMasterInvocationHandler.ServiceProcessor serviceProcessor = new KeyMasterInvocationHandler.ServiceProcessor();

        @SneakyThrows
        @Override
        public void run() {
            while (true) {
                Request request = work.take();
                Response r = new Response();
                r.resp = "Zool is cool: " + request.txt;
                request.sender.onResponse(request.id, r);
            }
        }
    }

    static class KeyMasterAvatarRunnable extends AbstractRunnable {
        KeyMasterRunnable serviceRunnable;
        KeyMasterInvocationHandler handler;
        KeyMasterAPI api;

        public KeyMasterAvatarRunnable(KeyMasterRunnable serviceRunnable) {
            this.serviceRunnable = serviceRunnable;

            handler = new KeyMasterInvocationHandler() {
                @Override
                String send(String requestMessage) {
                    System.out.println(requestMessage);
                    String res = serviceRunnable.serviceProcessor.process(requestMessage);
                    System.out.println(res);
                    return res;
                }
            };

//            handler.serviceProcessor = serviceRunnable.serviceProcessor;
            this.api = (KeyMasterAPI) Proxy.newProxyInstance(TestMessageBus.class.getClassLoader(), new Class[]{KeyMasterAPI.class}, handler);
        }

        @SneakyThrows
        String sendText(String msg) {
            Request request = new Request(this, reqCount++, msg);
            Transaction t = new Transaction(request);
            transactions.put(request.id, t);
            serviceRunnable.onRequest(request);
            Response response = t.response.take();
            return response.resp;
        }

        @SneakyThrows
        @Override
        public void run() {
            String resp = sendText("Hello Worl7686d!");
            System.out.println(resp);
        }
    }


    @Test
    void zoolTest() {

        KeyMasterRunnable keyMasterRunnable = new KeyMasterRunnable();
        keyMasterRunnable.serviceProcessor.service = keyMasterRunnable.service;
        Thread serviceThread = new Thread(keyMasterRunnable);
        serviceThread.start();

        keyMasterRunnable.service.ids.add("joe@cool");
        keyMasterRunnable.service.ids.add("joe@zool");

        KeyMasterAvatarRunnable keyMasterAvatarRunnable = new KeyMasterAvatarRunnable(keyMasterRunnable);
        keyMasterAvatarRunnable.serviceRunnable = keyMasterRunnable;

        Thread customerThread = new Thread(keyMasterAvatarRunnable);
        customerThread.start();

        KeyMasterAPI api = keyMasterAvatarRunnable.api;

        Assertions.assertEquals(keyMasterRunnable.service.ids.getFirst(), api.getDefaultId("sdfsdfsdf", 33));
        String[][] array = {{"sfdsdf", "sdfsdf"}, {"sdfsdf", "sdfsdf"}};

        Assertions.assertArrayEquals(array, api.getIdentities("Hello World!".getBytes()));
    }
}
