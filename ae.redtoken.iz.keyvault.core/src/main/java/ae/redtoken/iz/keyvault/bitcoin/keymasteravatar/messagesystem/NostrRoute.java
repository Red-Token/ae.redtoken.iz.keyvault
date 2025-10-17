package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import nostr.base.PublicKey;

import java.net.SocketAddress;

public class NostrRoute {
    public PublicKey receiverPublicKey;
    public String eventId;
    public SocketAddress socketAddress;
}
