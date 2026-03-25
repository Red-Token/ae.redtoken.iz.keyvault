package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.avatarctrl.AvatarCtrlStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.base.PublicKey;
import nostr.id.Identity;

import java.net.DatagramSocket;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class IZSystemAvatar3 {

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

    private PublicKey uplinkPubkey;
    // request coming from the user
    final DatagramSocket lowerSocket;
    boolean run = true;
    Map<Long, RouteEntry> paths = new HashMap<>();

    AvatarCtrlStackedService ss = new  AvatarCtrlStackedService();
    MasterRunnable<AvatarCtrlStackedService> mr = new MasterRunnable<>(ss);
    AvatarConnector<AvatarCtrlStackedService> connector;

    /**
     * class the handles traffic from the uplink, ie from KeyMaster
     */
    class UpLinkService extends LinkService {

        final ResponseSender<NostrRoute> responseSender = new ResponseSender<>(new NostrOverUdpSender(lowerSocket, identity));

        protected UpLinkService() {
            super(new NostrOverUdpReceiver(upperSocket), identity);

            processor = new MessageProcessor() {

                @SneakyThrows
                @Override
                public void onRequest(Request request, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    uplinkPubkey = info.route.senderPubKey;
                    upperSocket.connect(info.route.socketAddress);



                    ss.process(List.of(request.address), request.message);


                }

                @Override
                public void onResponse(Response response, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    RouteEntry re = paths.remove(response.id());

                    if (re.receivedRequestRoute == null) {
                        log.atError().log("No route found for: " + response.id());
                        return;
                    }

                    log.atInfo().log("UL: R:" + response.toString());
                    responseSender.sendMessage(response, re.receivedRequestRoute);
                }
            };
        }
    }

    /**
     * class that handles traffic from  the downlink
     */
    class DownLinkService extends LinkService {

        RequestSender<NostrRoute> sender = new RequestSender<>(new EncryptedNostrOverUdpSender(upperSocket, identity));

        protected DownLinkService() {
            super(new NostrOverUdpReceiver(lowerSocket), identity);

            processor = new MessageProcessor() {

                @Override
                public void onRequest(Request request, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    log.atInfo().log("DL R:" + request.toString());

                    paths.put(request.id(), new RouteEntry(info.route));
                    NostrRoute route = new NostrRoute();
                    route.eventId = info.route.eventId;
                    route.senderPubKey = uplinkPubkey;

                    sender.sendMessage(request, route);
                }

                @Override
                public void onResponse(Response response, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    log.atError().log("DL Received response, this should not happen:" + response.toString());
                }
            };
        }
    }

    public final ExecutorService executor;

    @SneakyThrows
    public IZSystemAvatar3(DatagramSocket upperSocket, Identity identity, PublicKey uplinkPubkey, int servicePort) {
        this.identity = identity;
        this.upperSocket = upperSocket;
        this.uplinkPubkey = uplinkPubkey;
        this.lowerSocket = new DatagramSocket(servicePort);

        executor = Executors.newCachedThreadPool();

        executor.execute(new UpLinkService());
        executor.execute(new DownLinkService());
    }
}
