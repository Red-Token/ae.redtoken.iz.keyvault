package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;

public class RequestReceiver<R> extends MessageReceiver<Request, R> {
    public RequestReceiver(AbstractLinkReceiver<R> receiver) {
        super(receiver, Request.class);
    }
}
