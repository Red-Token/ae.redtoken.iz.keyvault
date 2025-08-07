package ae.redtoken.iz;

import ae.redtoken.nostrjava.FilteredEventQueue;
import lombok.SneakyThrows;
import nostr.api.NIP44;
import nostr.base.IEvent;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.client.Client;
import nostr.context.impl.DefaultRequestContext;
import nostr.encryption.MessageCipher;
import nostr.encryption.nip44.MessageCipher44;
import nostr.event.BaseTag;
import nostr.event.Kind;
import nostr.event.impl.EncryptedPayloadEvent;
import nostr.event.impl.Filters;
import nostr.event.impl.TextNoteEvent;
import nostr.event.message.EventMessage;
import nostr.event.tag.PubKeyTag;
import nostr.id.Identity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

/**
 * Unit test for simple App.
 */
public class AppTest {
    public final static Map<String, String> RELAYS = Map.of("strfry", "ws://127.0.0.1:7777");

    @SneakyThrows
    @Test
    void testZool() {
        // Create the testevent
        long now = System.currentTimeMillis() / 1000;
        Identity identity = Identity.generateRandomIdentity();
        Identity identity2 = Identity.generateRandomIdentity();
        PublicKey pk = identity.getPublicKey();

        final String testMessage = "He-Man";
        TextNoteEvent nostrEvent = new TextNoteEvent(pk, List.of(), testMessage);
        nostrEvent.update();

        // Create a filter for the messages
        Filters filters = Filters.builder().since(now).authors(List.of(pk)).kinds(List.of(Kind.valueOf(nostrEvent.getKind()))).build();
        FilteredEventQueue nostrFilter = new FilteredEventQueue(filters);

        Client client = Client.getInstance();
        DefaultRequestContext requestContext = new DefaultRequestContext();
        requestContext.setRelays(RELAYS);
        client.connect(requestContext);

        client.send(nostrFilter.getReqMessage());

        Signature sign = identity.sign(nostrEvent);
        nostrEvent.setSignature(sign);

        // Send out the message
        client.send(new EventMessage(nostrEvent));

        IEvent take = nostrFilter.take();

        var nip44 = NIP44.getInstance(identity);

        TextNoteEvent textNoteEvent = new  TextNoteEvent(pk, List.of(), testMessage);

        BaseTag bt = new PubKeyTag(identity2.getPublicKey());

        EncryptedPayloadEvent ep = new EncryptedPayloadEvent(identity.getPublicKey(), List.of(bt), "ZOOL");
        ep.update();

        System.out.println(ep.getContent());

        NIP44.encrypt(identity, ep);

        System.out.println(ep.getKind());

        System.out.println(ep.getContent());

        String decrypt1 = NIP44.decrypt(identity2, ep);

        System.out.println(ep.getContent());

        String msg = "sfsdfsffsfsdf";
        String encrypt = NIP44.encrypt(identity, msg, identity2.getPublicKey());

        MessageCipher cipher = new MessageCipher44(identity.getPrivateKey().getRawData(), identity2.getPublicKey().getRawData());
        String encrypt1 = cipher.encrypt(msg);


        String decrypt = NIP44.decrypt(identity2, encrypt, identity.getPublicKey());

        MessageCipher cipher2 = new MessageCipher44(identity2.getPrivateKey().getRawData(), identity.getPublicKey().getRawData());
        String decrypt2 = cipher2.decrypt(encrypt1);

        System.out.println("The End");
    }
}
