package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.api.NIP44;
import nostr.base.PublicKey;
import nostr.event.impl.GenericEvent;
import nostr.event.tag.EventTag;
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
    Map<Long, RouteEntry> paths = new HashMap<>();

    /**
     * class the handles traffic from the uplink, ie from KeyMaster
     */
    class UpLinkService extends LinkService {

        final ResponseSender<NostrRoute> responseSender = new ResponseSender<>(new NostrOverUdpSender(lowerSocket, identity));

        protected UpLinkService() {
            super(new NostrOverUdpReceiver(upperSocket, identity));

            processor = new MessageProcessor() {

                @Override
                public void onRequest(Request request, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    throw new RuntimeException("Not implemented");
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

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                AbstractLinkReceiver.RouteInfo<NostrRoute> routeInfo = new AbstractLinkReceiver.RouteInfo<>();
                GenericEvent event = receiver.receiveEvent(routeInfo);

                NostrEncryptionType type = event.getTags().stream()
                        .filter(EncryptionTag.class::isInstance)
                        .map(EncryptionTag.class::cast)
                        .map(EncryptionTag::getType)
                        .findFirst()
                        .orElse(null);

                // Decrypt content if encrypted
                String decryptedContent = switch (type) {
                    case nip44 -> NIP44.decrypt(identity, event.getContent(), event.getPubKey());
                    case nip04 -> throw new RuntimeException("not implemented");
                    case null -> event.getContent();
                };

                // TODO we should check more here, like if we sent it out ans stuff
                boolean isResponse = event.getTags().stream().anyMatch(EventTag.class::isInstance);

                if(isResponse) {
                    Response response = LinkService.mapper.readValue(decryptedContent, Response.class);
                    processor.onResponse(response, routeInfo);
                } else  {
                    Request request = LinkService.mapper.readValue(decryptedContent, Request.class);
                    processor.onRequest(request, routeInfo);
                }
            }
        }
    }

    /**
     * class that handles traffic from  the downlink
     */
    class DownLinkService extends LinkService {

        RequestSender<NostrRoute> sender = new RequestSender<>(new EncryptedNostrOverUdpSender(upperSocket, identity));

        protected DownLinkService() {
            super(new NostrOverUdpReceiver(lowerSocket, identity));

            processor = new MessageProcessor() {

                @Override
                public void onRequest(Request request, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    log.atInfo().log("DL R:" + request.toString());

                    paths.put(request.id(), new RouteEntry(info.route));
                    NostrRoute route = new NostrRoute();
                    route.eventId = info.route.eventId;
                    route.receiverPublicKey = uplinkPubkey;

                    sender.sendMessage(request, route);
                }

                @Override
                public void onResponse(Response response, AbstractLinkReceiver.RouteInfo<NostrRoute> info) {
                    log.atError().log("DL Received response, this should not happen:" + response.toString());
                }
            };
        }

        @SneakyThrows
        @Override
        public void run() {

            RequestReceiver<NostrRoute> receiver = new RequestReceiver<>(this.receiver);

            while (run) {
                AbstractLinkReceiver.RouteInfo<NostrRoute> info = new AbstractLinkReceiver.RouteInfo<>();
                GenericEvent event = this.receiver.receiveEvent(info);

                NostrEncryptionType type = event.getTags().stream()
                        .filter(EncryptionTag.class::isInstance)
                        .map(EncryptionTag.class::cast)
                        .map(EncryptionTag::getType)
                        .findFirst()
                        .orElse(null);

                info.route.encryptionType = type;

                // Decrypt content if encrypted
                String decryptedContent = switch (type) {
                    case nip44 -> NIP44.decrypt(identity, event.getContent(), event.getPubKey());
                    case nip04 -> throw new RuntimeException("not implemented");
                    case null -> event.getContent();
                };

                boolean isResponse = event.getTags().stream().anyMatch(EventTag.class::isInstance);

                if(isResponse) {
                    throw new RuntimeException("not implemented");
                } else {
                    Class<Request> cls = Request.class;
                    Request request = LinkService.mapper.readValue(decryptedContent, cls);
                    processor.onRequest(request, info);
                }
            }
        }
    }

    public final ExecutorService executor;

    @SneakyThrows
    public IZSystemAvatar2(DatagramSocket upperSocket, Identity identity, PublicKey uplinkPubkey, int servicePort) {
        this.identity = identity;
        this.upperSocket = upperSocket;
        this.uplinkPubkey = uplinkPubkey;
        this.lowerSocket = new DatagramSocket(servicePort);

        executor = Executors.newCachedThreadPool();

        executor.execute(new UpLinkService());
        executor.execute(new DownLinkService());
    }
}
