package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import lombok.SneakyThrows;
import nostr.api.NIP44;
import nostr.base.PublicKey;
import nostr.event.BaseTag;
import nostr.event.impl.GenericEvent;
import nostr.event.message.EventMessage;
import nostr.event.tag.EventTag;
import nostr.event.tag.PubKeyTag;
import nostr.id.Identity;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class EncryptedNostrOverUdpSender extends AbstractLinkSender<NostrRoute> {

    static class KeyMasterEventBuilder {
        GenericEvent event;

        public KeyMasterEventBuilder(PublicKey publicKey) {
            this.event = new GenericEvent();
            event.setPubKey(publicKey);
            event.setKind(getKind());
        }

        protected int getKind() {
            return 7001;
        }

        public KeyMasterEventBuilder setTags(List<BaseTag> tags) {
            event.setTags(tags);
            return this;
        }

        GenericEvent build() {
            return event;
        }
    }

    final DatagramSocket socket;

    private final Identity sender;

    public EncryptedNostrOverUdpSender(DatagramSocket socket, Identity sender) {
        this.socket = socket;
        this.sender = sender;
    }


    @SneakyThrows
    public void sendPacket(byte[] packet, NostrRoute route) {

        List<BaseTag> tags = new ArrayList<>();
        if (route.eventId != null) {
            tags.add(new EventTag(route.eventId));
        }
        tags.add(new PubKeyTag(route.senderPubKey));
        tags.add(new EncryptionTag(NostrEncryptionType.nip44));


        GenericEvent genericEvent = new GenericEvent();
        genericEvent.setPubKey(sender.getPublicKey());
        genericEvent.setKind(7001);
        genericEvent.setTags(tags);
        genericEvent.setContent(NIP44.encrypt(sender, new String(packet), route.senderPubKey));
        genericEvent.update();
        sender.sign(genericEvent);

        sendDatagramPacket(genericEvent, route);
    }

    @SneakyThrows
    public void sendDatagramPacket(GenericEvent event, NostrRoute route) {
        EventMessage eventMessage = new EventMessage(event);

        byte[] data = eventMessage.encode().getBytes(StandardCharsets.UTF_8);

        SocketAddress address = route.socketAddress == null ? socket.getRemoteSocketAddress() : route.socketAddress;
        socket.send(new DatagramPacket(data, data.length, address));
    }
}
