package ae.redtoken.nostrtest;

import lombok.NonNull;
import nostr.base.Relay;
import nostr.base.annotation.CustomHandler;
import nostr.event.BaseMessage;
import nostr.event.message.EventMessage;

import java.util.logging.Level;

import static nostr.base.Command.EVENT;

@CustomHandler(command = EVENT)
public class EventCustomHandler extends BaseCustomCommandHandler {
    public EventCustomHandler() {
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

        if (subId == null) {
            log.log(Level.INFO, ">>> ZOOL Sending event {0} to relay {1}", new Object[]{event, relay});
        } else {
            log.log(Level.INFO, "<<< ZOOL Received EVENT {0} from relay {1} with subscription id {2}", new Object[]{event, relay, subId});
        }
    }

}
