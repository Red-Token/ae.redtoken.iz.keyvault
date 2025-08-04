package ae.redtoken.nostrtest;

import lombok.NonNull;
import nostr.base.IEvent;
import nostr.base.Relay;
import nostr.base.annotation.CustomHandler;
import nostr.event.BaseMessage;
import nostr.event.message.EventMessage;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import static nostr.base.Command.EVENT;

@CustomHandler(command = EVENT)
public class NostrTestEventHandler extends BaseCustomCommandHandler {

    public interface FluidEventHandler {
        void onEvent(IEvent event, BaseMessage message, Relay relay);
    }

    public static Map<String, FluidEventHandler> handlers = new HashMap<>();

    public NostrTestEventHandler() {
        super(EVENT);
    }

    /**
     * Log the event received from the relay
     *
     * @param message the message
     * @param relay   the relay
     */
    protected void onCommand(@NonNull BaseMessage message, @NonNull Relay relay) {
        var eventMessage = (EventMessage) message;
        var event = eventMessage.getEvent();
        var subId = eventMessage.getSubscriptionId();

        if(handlers.containsKey(subId)) {
            handlers.get(subId).onEvent(event, message, relay);
        }
    }

}
