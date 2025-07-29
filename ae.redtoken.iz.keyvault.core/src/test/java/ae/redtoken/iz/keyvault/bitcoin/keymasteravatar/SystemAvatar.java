package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import lombok.SneakyThrows;

import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;

public class SystemAvatar {
    // reply coming from the keymaster
    final DatagramSocket upperSocket;

    // request coming from the user
    final DatagramSocket lowerSocket;
    private final boolean run = true;
    Map<Integer, SocketAddress> paths = new HashMap<>();

    /**
     * class the handles traffic from the uplink
     */
    class UpLinkService extends LinkService {
        ResponseReceiver<SocketAddress> responseReceiver = new ResponseReceiver<>(new UdpLinkReceiver(upperSocket));
        ResponseSender<SocketAddress> responseSender = new ResponseSender<>(new UdpLinkSender(lowerSocket));

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                Response response = responseReceiver.receive();
                SocketAddress sa = paths.remove(response.id());

                if (sa == null) {
                    throw new RuntimeException("Could not find socket address");
                }

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

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                AbstractLinkReceiver.RouteInfo<SocketAddress> info = new AbstractLinkReceiver.RouteInfo<>();
                Request request = receiver.receive(info);
                paths.put(request.id(), info.route);
                sender.sendMessage(request);
            }
        }
    }

    @SneakyThrows
    public SystemAvatar(DatagramSocket upperSocket) {
        this.upperSocket = upperSocket;
        this.lowerSocket = new DatagramSocket(AvatarSpawnPoint.SERVICE_PORT);

        // Messages coming from the user to the master
        Thread upLinkService = new Thread(new UpLinkService());
        upLinkService.start();

        // Reply coming from the keymaster
        Thread downLinkService = new Thread(new DownLinkService());
        downLinkService.start();
    }
}
