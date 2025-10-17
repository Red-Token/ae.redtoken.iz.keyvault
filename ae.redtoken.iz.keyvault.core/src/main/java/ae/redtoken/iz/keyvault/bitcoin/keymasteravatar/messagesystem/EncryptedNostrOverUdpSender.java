package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import lombok.SneakyThrows;
import nostr.api.NIP44;
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
        tags.add(new PubKeyTag(route.receiverPublicKey));

        GenericEvent genericEvent = new GenericEvent();
        genericEvent.setPubKey(sender.getPublicKey());
        genericEvent.setKind(7001);
        genericEvent.setTags(tags);
        genericEvent.setContent(NIP44.encrypt(sender, new String(packet), route.receiverPublicKey));
        genericEvent.update();
        sender.sign(genericEvent);

        EventMessage eventMessage = new EventMessage(genericEvent);

        byte[] data = eventMessage.encode().getBytes(StandardCharsets.UTF_8);

        SocketAddress address = route.socketAddress == null ? socket.getRemoteSocketAddress() : route.socketAddress;
        socket.send(new DatagramPacket(data, data.length, address));
    }
}
