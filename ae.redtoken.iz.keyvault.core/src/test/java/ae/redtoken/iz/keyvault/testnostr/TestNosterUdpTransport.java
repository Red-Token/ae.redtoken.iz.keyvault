package ae.redtoken.iz.keyvault.testnostr;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import lombok.SneakyThrows;
import nostr.api.NIP01;
import nostr.api.NIP44;
import nostr.api.Nostr;
import nostr.base.IEncoder;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.base.annotation.Event;
import nostr.event.BaseTag;
import nostr.event.Kind;
import nostr.event.impl.EncryptedPayloadEvent;
import nostr.event.impl.GenericEvent;
import nostr.event.message.EventMessage;
import nostr.event.tag.EventTag;
import nostr.id.Identity;
import nostr.util.NostrException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public class TestNosterUdpTransport {

    static String serialize(GenericEvent event) throws NostrException {
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


    public abstract class NIPAAEvent extends GenericEvent {
        public NIPAAEvent(PublicKey pubKey, Kind kind, List<BaseTag> tags) {
            super(pubKey, kind, tags);
        }

        public NIPAAEvent(PublicKey pubKey, Kind kind, List<BaseTag> tags, String content) {
            super(pubKey, kind, tags, content);
        }

        public NIPAAEvent(PublicKey sender, Integer kind, List<BaseTag> tags, String content) {
            super(sender, kind, tags, content);
        }

        public NIPAAEvent() {
        }
    }

    @Event(
            name = "RequestEvent",
            nip = 600
    )
    public class KeyMasterRequestEvent extends GenericEvent {
        public KeyMasterRequestEvent(PublicKey pubKey, List<BaseTag> tags, String content) {
            super(pubKey, 7101, tags, content);
        }
    }

    @SneakyThrows
    @Test
    void testNostrUdpTransport() throws JsonProcessingException {


        // Step 1: Generate a new identity (key pair)
        Identity identity = Identity.generateRandomIdentity();
        String privateKey = identity.getPrivateKey().toString();
        String publicKey = identity.getPublicKey().toString();
        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);

        // Step 2: Create a text note data
        KeyMasterRequestEvent textNote = new KeyMasterRequestEvent(
                identity.getPublicKey(), List.of(new EventTag("")),
                "Hello, Nostr! This is a test post from nostr-java."
        );

        GenericEvent genericEvent = new GenericEvent();
        genericEvent.setPubKey(identity.getPublicKey());
        genericEvent.setNip(6666);
//        genericEvent.setTags(List.of(new EventTag(""), new PubKeyTag(identity.getPublicKey())));
        genericEvent.setContent("ssh_request");

        // Antingen som UDP, eller som Intent och då kommer då som strings i en


        Signature sign = identity.sign(textNote);

        System.out.println(Base64.getEncoder().encodeToString(textNote.get_serializedEvent()));

        EventMessage eventMessage = new EventMessage(textNote);

        String encode = eventMessage.encode();
        System.out.println("Encode: " + encode);
        Object[] arr = IEncoder.MAPPER.readValue(encode, Object[].class);
        EventMessage decode = EventMessage.decode(arr, IEncoder.MAPPER);
        GenericEvent event = (GenericEvent) decode.getEvent();
        event.set_serializedEvent(serialize(event).getBytes(StandardCharsets.UTF_8));
        boolean verify = NIP01.getInstance().verify(event);

        Assertions.assertTrue(verify);

        Identity identity2 = Identity.generateRandomIdentity();

        Nostr instance = NIP44.getInstance(identity);

        String encrypt = NIP44.encrypt(identity2, "Zolana", identity.getPublicKey());

        String decrypt = NIP44.decrypt(identity, encrypt, identity2.getPublicKey());

        System.out.println(decrypt);

        Request  rq = new Request();
        Response rsp = new Response();

        System.out.println("The end!");
    }
}
