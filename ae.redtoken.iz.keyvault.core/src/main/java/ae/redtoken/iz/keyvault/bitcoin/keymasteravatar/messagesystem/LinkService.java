package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.MessageProcessor;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NonNull;
import lombok.SneakyThrows;
import nostr.api.NIP44;
import nostr.event.impl.GenericEvent;
import nostr.event.tag.EventTag;
import nostr.id.Identity;
import org.jetbrains.annotations.NotNull;

public abstract class LinkService implements Runnable {
    protected static ObjectMapper mapper = new ObjectMapper();

    protected final NostrOverUdpReceiver receiver;
    protected MessageProcessor processor;
    private final @NonNull Identity identity;
    boolean run = true;

    protected LinkService(NostrOverUdpReceiver receiver, @NotNull Identity identity) {
        this.receiver = receiver;
        this.identity = identity;
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
