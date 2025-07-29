package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;

public class ResponseSender<R> extends MessageSender<Response, R> {
    public ResponseSender(AbstractLinkSender<R> sender) {
        super(sender);
    }
}
