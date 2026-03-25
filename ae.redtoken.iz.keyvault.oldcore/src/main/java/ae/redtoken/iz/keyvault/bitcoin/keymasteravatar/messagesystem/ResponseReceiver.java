package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;

public class ResponseReceiver<R> extends MessageReceiver<Response, R> {
    public ResponseReceiver(AbstractLinkReceiver<R> receiver) {
        super(receiver, Response.class);
    }
}
