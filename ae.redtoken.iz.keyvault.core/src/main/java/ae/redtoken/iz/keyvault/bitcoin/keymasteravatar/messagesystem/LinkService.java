package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import com.fasterxml.jackson.databind.ObjectMapper;

public abstract class LinkService implements Runnable {
    protected static ObjectMapper mapper = new ObjectMapper();

    protected final NostrOverUdpReceiver receiver;

    protected LinkService(NostrOverUdpReceiver receiver) {
        this.receiver = receiver;
    }

//    static {
//        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
//    }

}
