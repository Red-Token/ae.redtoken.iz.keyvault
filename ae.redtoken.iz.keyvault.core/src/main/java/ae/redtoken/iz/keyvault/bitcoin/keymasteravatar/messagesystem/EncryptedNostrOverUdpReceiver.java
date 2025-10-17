package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.api.NIP01;
import nostr.api.NIP44;
import nostr.base.IEncoder;
import nostr.event.impl.GenericEvent;
import nostr.event.message.EventMessage;
import nostr.id.Identity;
import nostr.util.NostrException;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Slf4j
public class EncryptedNostrOverUdpReceiver extends AbstractLinkReceiver<NostrRoute> {

    public static String serialize(GenericEvent event) throws NostrException {
        ObjectMapper mapper = IEncoder.MAPPER;
        ArrayNode arrayNode = JsonNodeFactory.instance.arrayNode();

        try {
            arrayNode.add(0);
            arrayNode.add(event.getPubKey().toString());
            arrayNode.add(event.getCreatedAt());
            arrayNode.add(event.getKind());
            arrayNode.add(mapper.valueToTree(event.getTags()));
            arrayNode.add(event.getContent());
            return mapper.writeValueAsString(arrayNode);
        } catch (JsonProcessingException e) {
            throw new NostrException(e);
        }
    }

    final byte[] buffer = new byte[AvatarSpawnPoint.MAX_PACKET_SIZE];
    final DatagramSocket socket;
    private final Identity recipient;

    public EncryptedNostrOverUdpReceiver(DatagramSocket socket, Identity recipient) {
        this.socket = socket;
        this.recipient = recipient;
    }

    @SneakyThrows
    public byte[] receivePacket(RouteInfo<NostrRoute> routeInfo) {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        log.info("Received length" + packet.getLength());

        byte[] data = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
        EventMessage eventMessage = EventMessage.decode(IEncoder.MAPPER.readValue(data, Object[].class), IEncoder.MAPPER);
        GenericEvent event = (GenericEvent) eventMessage.getEvent();
        event.set_serializedEvent(serialize(event).getBytes(StandardCharsets.UTF_8));

        boolean verify = NIP01.getInstance().verify(event);

        if (!verify) {
            throw new RuntimeException("Verification failed!");
        }

        if (routeInfo != null) {
            routeInfo.route = new NostrRoute();
            routeInfo.route.socketAddress = packet.getSocketAddress();
            routeInfo.route.receiverPublicKey = event.getPubKey();
            routeInfo.route.eventId = event.getId();
        }

        return NIP44.decrypt(recipient, event.getContent(), event.getPubKey()).getBytes(StandardCharsets.UTF_8);
    }
}
