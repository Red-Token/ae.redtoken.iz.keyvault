package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class IZSystemAvatar {





    // reply coming from the keymaster
    final DatagramSocket upperSocket;

    // request coming from the user
    final DatagramSocket lowerSocket;
    boolean run = true;
    Map<Long, SocketAddress> paths = new HashMap<>();

    /**
     * class the handles traffic from the uplink
     */
    class UpLinkService extends LinkService {
        ResponseReceiver<SocketAddress> responseReceiver = new ResponseReceiver<>(new UdpLinkReceiver(upperSocket));
        ResponseSender<SocketAddress> responseSender = new ResponseSender<>(new UdpLinkSender(lowerSocket));

        protected UpLinkService() {
            super(null);
        }

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                Response response = responseReceiver.receive();
                SocketAddress sa = paths.remove(response.id());

                if (sa == null) {
                    throw new RuntimeException("Could not find socket address");
                }

                log.atInfo().log("UL: R:" + response.toString());

                responseSender.sendMessage(response, sa);
            }
        }
    }

    /**
     * class that handles traffic from  the downlink
     */
    class DownLinkService extends LinkService {
        RequestReceiver<SocketAddress> receiver = new RequestReceiver<>(new UdpLinkReceiver(lowerSocket));
        RequestSender<SocketAddress> sender = new RequestSender<>(new UdpLinkSender(upperSocket));

        protected DownLinkService() {
            super(null);
        }

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                AbstractLinkReceiver.RouteInfo<SocketAddress> info = new AbstractLinkReceiver.RouteInfo<>();
                Request request = receiver.receive(info);
                paths.put(request.id(), info.route);

                log.atInfo().log("DL R:" + request.toString());

                sender.sendMessage(request);
            }
        }
    }

    public final ExecutorService executor;

    @SneakyThrows
    public IZSystemAvatar(DatagramSocket upperSocket, int servicePort) {
        this.upperSocket = upperSocket;
        this.lowerSocket = new DatagramSocket(servicePort);

        executor = Executors.newCachedThreadPool();

        executor.execute(new UpLinkService());
        executor.execute(new DownLinkService());
    }
}
