package ae.redtoken.iz.keyvault.testnostr;

import nostr.api.NIP01;
import nostr.event.Kind;
import nostr.event.impl.Filters;
import nostr.event.impl.TextNoteEvent;
import nostr.event.tag.EventTag;
import nostr.id.Identity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;


public class TestNostr {
    final static Map< String, String> RELAYS = Map.of("strfry", "ws://127.0.0.1:7777");

    @Test
    void yelp() throws Exception {

        // Step 1: Generate a new identity (key pair)
        Identity identity = Identity.generateRandomIdentity();
        String privateKey = identity.getPrivateKey().toString();
        String publicKey = identity.getPublicKey().toString();
        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);

        // Step 2: Create a text note event
        TextNoteEvent textNote = new TextNoteEvent(
                identity.getPublicKey(), List.of(new EventTag("")),
                "Hello, Nostr! This is a test post from nostr-java."
        );

        identity.sign(textNote);

        var sender = Identity.generateRandomIdentity();
        NIP01<TextNoteEvent> nip01 = new NIP01<>(sender);
//        GenericEvent send = nip01.createTextNoteEvent("Hello Nostr World!").setSender(sender).sign().send(RELAYS);

        NIP01<TextNoteEvent> note = nip01.createTextNoteEvent("SSSSSS");

        note.setSender(sender);
        note.sign();
        note.send(RELAYS);

        System.out.println("Note sent: " + note);

        Thread.sleep(5000);

        System.out.println("Note sent: " + note);

        Filters filters = Filters.builder().kinds(List.of(Kind.TEXT_NOTE)).build();

        nip01.setRelays(RELAYS).send(filters, "sub_" + sender.getPublicKey());



        Thread.sleep(5000);
        System.out.println("Note sent: " + filters);


//        // Step 4: Connect to a relay and publish the event
//        String relayUrl = "wss://nostr-pub.wellorder.net";
//        Client client = Client.getInstance();
//        client.connect()
//        client.send(textNote); // Publish the signed event
//        System.out.println("Event published to relay: " + textNote.getId());



    }
}
