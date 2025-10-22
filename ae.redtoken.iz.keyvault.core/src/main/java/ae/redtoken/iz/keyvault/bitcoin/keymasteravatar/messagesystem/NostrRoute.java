package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import nostr.base.PublicKey;

import java.net.SocketAddress;

public class NostrRoute {
    public PublicKey senderPubKey;
    public String eventId;
    public SocketAddress socketAddress;
    public NostrEncryptionType encryptionType;
}
