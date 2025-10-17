package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.base.PublicKey;
import nostr.id.Identity;

import java.net.DatagramSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class IZSystemAvatar2 {

    static class RouteEntry {
        NostrRoute receivedRequestRoute;
        NostrRoute sendRequestRoute;
        NostrRoute receivedResponseRoute;

        public RouteEntry(NostrRoute receivedRequestRoute) {
            this.receivedRequestRoute = receivedRequestRoute;
        }
    }

    private final Identity identity;

    // reply coming from the keymaster
    final DatagramSocket upperSocket;

    private final PublicKey uplinkPubkey;
    // request coming from the user
    final DatagramSocket lowerSocket;
    boolean run = true;
    Map<Integer, RouteEntry> paths = new HashMap<>();

    /**
     * class the handles traffic from the uplink
     */
    class UpLinkService extends LinkService {
        ResponseReceiver<NostrRoute> responseReceiver = new ResponseReceiver<>(new EncryptedNostrOverUdpReceiver(upperSocket, identity));
        ResponseSender<NostrRoute> responseSender = new ResponseSender<>(new NostrOverUdpSender(lowerSocket, identity));

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                AbstractLinkReceiver.RouteInfo<NostrRoute> routeInfo = new AbstractLinkReceiver.RouteInfo<>();
                Response response = responseReceiver.receive(routeInfo);
                RouteEntry re = paths.remove(response.id());

                if (re.receivedRequestRoute == null) {
                    throw new RuntimeException("Could not find route for id " + response.id());
                }

                log.atInfo().log("UL: R:" + response.toString());

                responseSender.sendMessage(response, re.receivedRequestRoute);
            }
        }
    }

    /**
     * class that handles traffic from  the downlink
     */
    class DownLinkService extends LinkService {
        RequestReceiver<NostrRoute> receiver = new RequestReceiver<>(new NostrOverUdpReceiver(lowerSocket, identity));
        RequestSender<NostrRoute> sender = new RequestSender<>(new EncryptedNostrOverUdpSender(upperSocket, identity));

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                AbstractLinkReceiver.RouteInfo<NostrRoute> info = new AbstractLinkReceiver.RouteInfo<>();
                Request request = receiver.receive(info);
                paths.put(request.id(), new RouteEntry(info.route));

                log.atInfo().log("DL R:" + request.toString());

                NostrRoute route = new  NostrRoute();
                route.eventId = info.route.eventId;
                route.receiverPublicKey = uplinkPubkey;

                sender.sendMessage(request, route);
            }
        }
    }

    public final ExecutorService executor;

    @SneakyThrows
    public IZSystemAvatar2(DatagramSocket upperSocket, Identity identity,  PublicKey uplinkPubkey, int servicePort) {
        this.identity =  identity;
        this.upperSocket = upperSocket;
        this.uplinkPubkey = uplinkPubkey;
        this.lowerSocket = new DatagramSocket(servicePort);

        executor = Executors.newCachedThreadPool();

        executor.execute(new UpLinkService());
        executor.execute(new DownLinkService());
    }
}
