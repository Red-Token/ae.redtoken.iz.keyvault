package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;

public class RequestSender<R> extends MessageSender<Request, R> {
    public RequestSender(AbstractLinkSender<R> sender) {
        super(sender);
    }
}
