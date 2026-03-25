package ae.redtoken.nostrtest;

import nostr.base.IEvent;
import nostr.event.impl.Filters;
import nostr.event.message.ReqMessage;

import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

public class FilteredEventQueue extends LinkedBlockingQueue<IEvent> {
    final Filters filters;
    final String subId;

    public FilteredEventQueue(Filters filters) {
        this.filters = filters;
        this.subId = "subId-" + System.currentTimeMillis();
        NostrTestEventHandler.handlers.put(subId, (event, message, relay) -> add(event));
    }

    public ReqMessage getReqMessage() {
        return new ReqMessage(subId, List.of(filters));
    }
}
