package ae.redtoken.iz.keyvault.testnostr.sss;

import ae.redtoken.nostrtest.NostrTestEventHandler;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.SneakyThrows;
import nostr.api.EventNostr;
import nostr.api.NIP01;
import nostr.api.factory.EventFactory;
import nostr.base.PrivateKey;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.crypto.schnorr.Schnorr;
import nostr.event.BaseTag;
import nostr.event.Kind;
import nostr.event.impl.Filters;
import nostr.event.impl.GenericEvent;
import nostr.event.impl.TextNoteEvent;
import nostr.id.Identity;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Test;

import java.util.Currency;
import java.util.List;
import java.util.Map;


public class TestNostr {
    public final static Map<String, String> RELAYS = Map.of("strfry", "ws://127.0.0.1:7777");

    static class NIP0666Event extends GenericEvent {
        public NIP0666Event(PublicKey sender, Kind kind, List<BaseTag> tags, String content) {
            super(sender, kind, tags, content);
        }

        public NIP0666Event(GenericEvent event) {
            super(event.getPubKey(), event.getKind(), event.getTags(), event.getContent());
            this.setSignature(event.getSignature());
            this.setCreatedAt(event.getCreatedAt());
            this.setId(event.getId());
        }
    }

    static class NIP0666ArkQuotationEvent extends NIP0666Event {
        public NIP0666ArkQuotationEvent(@NonNull PublicKey pubKey, @NonNull List<BaseTag> tags, @NonNull String content) {
            super(pubKey, Kind.ARK_QUOTATION, tags, content);
        }

        public NIP0666ArkQuotationEvent(GenericEvent event) {
            super(event);
        }
    }

    @Data
    @EqualsAndHashCode(callSuper = false)
    static class NIP0666EventFactory extends EventFactory<NIP0666Event> {

        public NIP0666EventFactory(Identity sender, String content) {
            super(sender, content);
        }


        @Override
        public NIP0666Event create() {
            return new NIP0666Event(this.getSender(), Kind.ARK_REQUEST, this.getTags(), this.getContent());
        }
    }

    @Data
    @EqualsAndHashCode(callSuper = false)
    static class NIP0666ArkQuotationEventFactory extends EventFactory<NIP0666Event> {

        public NIP0666ArkQuotationEventFactory(Identity sender, String content) {
            super(sender, content);
        }


        @Override
        public NIP0666ArkQuotationEvent create() {
            return new NIP0666ArkQuotationEvent(this.getSender(), this.getTags(), this.getContent());
        }
    }

    static class NIP0666<T extends NIP0666Event> extends EventNostr<T> {
        /**
         * Create a replaceable event
         *
         * @param content the content
         */
        public NIP0666<T> createReplaceableEvent(String content) {
            var event = new NIP0666EventFactory(this.getSender(), content).create();
            this.setEvent((T) event);
            return this;
        }
    }

    @SneakyThrows
    @Test
    void testYelp2() {

        Identity sender = Identity.generateRandomIdentity();
        NIP01<TextNoteEvent> nip01 = new NIP01<>(sender);

        NIP01<TextNoteEvent> note = nip01.createTextNoteEvent("SSSSSS");
        note.setSender(sender);
//        TextNoteEvent event1 = note.getEvent();

        PrivateKey pk = new PrivateKey("9bec12a03568a8b7be6e2434d11fad6f6c7bb9acc52019f6774555161224c1bb");
        byte[] publicKeyBytes = Schnorr.genPubKey(pk.getRawData());

        System.out.println(NostrUtil.bytesToHex(publicKeyBytes));

        PublicKey publicKey = new PublicKey(publicKeyBytes);

        Identity identity2 = Identity.create(pk.toHexString());

//        TextNoteEvent event1 = new TextNoteEvent(sender.getPublicKey(), List.of(), "He-Man");

        TextNoteEvent event1 = new TextNoteEvent(identity2.getPublicKey(), List.of(), "He-Man");

        event1.update();

        ObjectMapper om = new ObjectMapper();

        // To KM we send
        String s = om.writeValueAsString(event1);

        System.out.println(s);

        String ss = "{\"id\":\"f36b5a29720775c1b1f33bf05526313abfe698a9c47b191e1a658029fbe8f2bd\",\"kind\":1,\"content\":\"He-Man\",\"pubkey\":\"1d45aa7ff76e24d3dff39c3e2011e48470cb569e4c7ac1750fd2e6bfa3ed60e2\",\"created_at\":1754232352,\"tags\":[],\"sig\":null}";

        // In KM we do
        GenericEvent ge = om.readValue(ss, GenericEvent.class);
        System.out.println(ge.getCreatedAt());
//        ge.update();
        System.out.println(ge.getCreatedAt());
        System.out.println(ge.getCreatedAt());

        // To KV we send
        byte[] pubkey = identity2.getPublicKey().getRawData();
        byte[] sha256 = NostrUtil.hexToBytes(ge.getId());

        byte[] randomByteArray = NostrUtil.createRandomByteArray(32);

        // From KV we get
//        byte[] sign1 = Schnorr.sign(sha256, sender.getPrivateKey().getRawData(), randomByteArray);
        byte[] sign1 = Schnorr.sign(sha256, identity2.getPrivateKey().getRawData(), randomByteArray);

        // From KM we get
        Signature signature = new Signature();
        signature.setRawData(sign1);
//        signature.setPubKey(sender.getPublicKey());
        signature.setPubKey(identity2.getPublicKey());

        String sigString = signature.toString();

        Signature signature2 = new Signature();
        signature2.setRawData(NostrUtil.hexToBytes(sigString));
        signature2.setPubKey(event1.getPubKey());

        ge.setSignature(signature2);

//        event1.setSignature(signature2);
//        event1.setSignature(signature);

        Thread.sleep(1000);

//        note.send(event1, RELAYS);

        note.send(ge, RELAYS);

        Thread.sleep(1000);

    }

    @Test
    void yelp() throws Exception {

        // Step 1: Generate a new identity (key pair)
//        Identity identity = Identity.generateRandomIdentity();
//        String privateKey = identity.getPrivateKey().toString();
//        String publicKey = identity.getPublicKey().toString();
//        System.out.println("Private Key: " + privateKey);
//        System.out.println("Public Key: " + publicKey);

//        // Step 2: Create a text note event
//        TextNoteEvent textNote = new TextNoteEvent(
//                identity.getPublicKey(), List.of(new EventTag("")),
//                "Hello, Nostr! This is a test post from nostr-java."
//        );
//
//        identity.sign(textNote);



        Identity sender = Identity.generateRandomIdentity();
        NIP01<TextNoteEvent> nip01 = new NIP01<>(sender);

        NIP01<TextNoteEvent> note = nip01.createTextNoteEvent("SSSSSS");
        note.setSender(sender);
//        TextNoteEvent event1 = note.getEvent();

        TextNoteEvent event1 = new TextNoteEvent(sender.getPublicKey(), List.of(), "He-Man");



//        event.update();
//        log.log(Level.FINER, "Serialized event: {0}", new String(event.get_serializedEvent()));
//        byte[] signedHashedSerializedEvent = Schnorr.sign(NostrUtil.sha256(event.get_serializedEvent()), this.getPrivateKey().getRawData(), this.generateAuxRand());
//        Signature signature = new Signature();
//        signature.setRawData(signedHashedSerializedEvent);
//        signature.setPubKey(this.getPublicKey());
//        event.setSignature(signature);

        event1.update();

        ObjectMapper om = new ObjectMapper();

        // To KM we send
        String s = om.writeValueAsString(event1);

        // In KM we do
        GenericEvent ge = om.readValue(s, GenericEvent.class);
        ge.update();

        // To KV we send
        byte[] pubkey = sender.getPublicKey().getRawData();
        byte[] sha256 = NostrUtil.sha256(ge.get_serializedEvent());

        byte[] randomByteArray = NostrUtil.createRandomByteArray(32);

        // From KV we get
        byte[] sign1 = Schnorr.sign(sha256, sender.getPrivateKey().getRawData(), randomByteArray);

        // From KM we get
        Signature signature = new Signature();
        signature.setRawData(sign1);
        signature.setPubKey(sender.getPublicKey());

        String sigString = signature.toString();

        Signature signature2 = new Signature();
        signature2.setRawData(NostrUtil.hexToBytes(sigString));
        signature2.setPubKey(event1.getPubKey());
        event1.setSignature(signature2);
//        event1.setSignature(signature);
        note.send(event1, RELAYS);
//
//
//        Signature sign = sender.sign(event1);
//
//        event1.setSignature(sign);

        System.out.println(event1);

//        note.sign();
//        note.send(RELAYS);

        System.out.println("Note sent: " + note);

        Thread.sleep(5000);

        System.out.println("Note sent: " + note);

        Filters filters = Filters.builder().kinds(List.of(Kind.ARK_REQUEST)).build();

        String subId = "sub_" + sender.getPublicKey();

        NostrTestEventHandler.handlers.put(subId, (event, message, relay) -> {
            NIP0666Event e = new NIP0666Event((GenericEvent) event);
            System.out.println(e);
        });

        nip01.setRelays(RELAYS).send(filters, subId);

        Thread.sleep(5000);
        System.out.println("Note sent: " + filters);

        NIP0666<NIP0666Event> nip0666 = new NIP0666<>();
        nip0666.setSender(sender);

        NIP0666<NIP0666Event> replaceableEvent = nip0666.createReplaceableEvent("Oh solomio");
        replaceableEvent.setSender(sender);
        replaceableEvent.sign();
        replaceableEvent.send(RELAYS);

        Thread.sleep(5000);
        System.out.println("THE END!");
    }

    public static class ArkQuotationContent {
        public String pubkey;
        public int amount;
        public ArkList arks = new ArkList();
        public ArkOffer offer = new ArkOffer();

        public ArkQuotationContent() {
        }
    }

    public static class ArkList {
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String[] include;
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String[] exclude;
        public boolean includeOnly = false;

        public ArkList() {
        }
    }

    public static class ArkOffer {
        private Currency currency;

        @JsonGetter("currency")
        public String getCurrencyCode() {
            return currency.getCurrencyCode();
        }

        @JsonSetter("currency")
        public void setCurrencyCode(String code) {
            this.currency = Currency.getInstance(code);
        }

        public ArkOfferItems[] items;
        public String vat;
    }

    public static class ArkOfferItems {
        public String description;
        public double quantity;
        public double price;

        public ArkOfferItems() {
        }

        public ArkOfferItems(String description, double quantity, double price) {
            this.description = description;
            this.quantity = quantity;
            this.price = price;
        }
    }

    @Test
    void testCrateJson() throws JsonProcessingException {

        ObjectMapper om = new ObjectMapper();
        ArkQuotationContent aqc = new ArkQuotationContent();

        aqc.amount = 30000;
        aqc.pubkey = "WHATEVER";
        aqc.arks.includeOnly = true;
        aqc.arks.include = new String[]{"myarc"};
        aqc.offer.currency = Currency.getInstance("USD");
        aqc.offer.items = new ArkOfferItems[]{
                new ArkOfferItems("Pepperoni", 1, 3.0)
        };
        aqc.offer.vat = "5%";

        String x = om.writeValueAsString(aqc);
        System.out.println(x);
    }
}
