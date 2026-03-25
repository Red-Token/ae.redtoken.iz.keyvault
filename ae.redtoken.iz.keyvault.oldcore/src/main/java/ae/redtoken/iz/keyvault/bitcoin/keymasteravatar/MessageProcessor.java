package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.AbstractLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrRoute;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;

public interface MessageProcessor {
    void onRequest(Request request, AbstractLinkReceiver.RouteInfo<NostrRoute> info);

    void onResponse(Response response, AbstractLinkReceiver.RouteInfo<NostrRoute> info);
}
