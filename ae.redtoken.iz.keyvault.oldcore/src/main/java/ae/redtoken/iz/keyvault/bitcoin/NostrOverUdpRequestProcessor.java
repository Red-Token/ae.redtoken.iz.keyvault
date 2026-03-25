package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import nostr.id.Identity;

import java.net.DatagramSocket;

public class NostrOverUdpRequestProcessor extends AbstractRequestProcessor<NostrRoute> {
    public NostrOverUdpRequestProcessor(KeyMasterExecutor kmr, DatagramSocket socket, Identity identity) {
        super(kmr, new EncryptedNostrOverUdpReceiver(socket, identity), new EncryptedNostrOverUdpSender(socket, identity));
    }
}
