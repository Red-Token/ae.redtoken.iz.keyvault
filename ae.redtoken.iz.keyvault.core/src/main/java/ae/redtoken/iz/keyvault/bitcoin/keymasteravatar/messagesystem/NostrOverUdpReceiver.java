package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.api.Nostr;
import nostr.base.IEncoder;
import nostr.event.BaseTag;
import nostr.event.impl.GenericEvent;
import nostr.event.json.codec.GenericTagDecoder;
import nostr.event.json.deserializer.TagDeserializer;
import nostr.event.message.EventMessage;
import nostr.event.tag.EventTag;
import nostr.event.tag.PubKeyTag;
import nostr.util.NostrException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

@Slf4j
public class NostrOverUdpReceiver extends AbstractLinkReceiver<NostrRoute> {

    static {
        IEncoder.MAPPER.addMixIn(BaseTag.class, BaseTagMixin.class);
    }

    @JsonDeserialize(using = Testz.class)
    static public abstract class BaseTagMixin {
    }


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

    public NostrOverUdpReceiver(DatagramSocket socket) {
        this.socket = socket;
    }

    @SneakyThrows
    protected byte[] receiveByteArray(RouteInfo<SocketAddress> routeInfo) {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        log.info("Received length" + packet.getLength());

        routeInfo.route = packet.getSocketAddress();

        return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
    }

    static class Testz<T extends BaseTag> extends TagDeserializer<T> {

        Map<String, Function<JsonNode, T>> calls = new HashMap<>();

        Testz() {
            calls.put("e", EventTag::deserialize);
            calls.put("p", PubKeyTag::deserialize);
            calls.put("encryption", EncryptionTag::deserialize);
        }

        @Override
        public T deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
            System.out.println("Victory!");

            JsonNode node = jsonParser.getCodec().readTree(jsonParser);
            // Extract relevant data from the JSON node
            String code = node.get(0).asText();

            if (calls.containsKey(code)) {
                return calls.get(code).apply(node);
            }

            return (T) new GenericTagDecoder<>().decode(node.toString());
        }
    }


    @SneakyThrows
    public GenericEvent receiveEvent(RouteInfo<NostrRoute> routeInfo) {
        RouteInfo<SocketAddress> udpRouteInfo = new RouteInfo<>();
        byte[] data = receiveByteArray(udpRouteInfo);


        Set<Object> registeredModuleIds = IEncoder.MAPPER.getRegisteredModuleIds();

//        SimpleModule module = new SimpleModule();
//        module.addDeserializer(BaseTag.class, new Testz());
//        IEncoder.MAPPER.registerModule(module);


        // Receive packet
        EventMessage eventMessage = EventMessage.decode(IEncoder.MAPPER.readValue(data, Object[].class), IEncoder.MAPPER);
        GenericEvent event = (GenericEvent) eventMessage.getEvent();
        event.set_serializedEvent(serialize(event).getBytes(StandardCharsets.UTF_8));

        // Verify the packet
        if (!Nostr.getInstance().verify(event)) {
            throw new RuntimeException("Verification failed!");
        }

        if (routeInfo != null) {
            routeInfo.route = new NostrRoute();
            routeInfo.route.socketAddress = udpRouteInfo.route;
            routeInfo.route.receiverPublicKey = event.getPubKey();
            routeInfo.route.eventId = event.getId();
        }

        return event;
    }


    @SneakyThrows
    public byte[] receivePacket(RouteInfo<NostrRoute> routeInfo) {
        GenericEvent event = receiveEvent(routeInfo);
        return event.getContent().getBytes(StandardCharsets.UTF_8);
    }
}
