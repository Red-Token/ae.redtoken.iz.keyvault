package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.UdpLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.UdpLinkSender;

import java.net.DatagramSocket;
import java.net.SocketAddress;

public class UdpRequestProcessor extends AbstractRequestProcessor<SocketAddress> {
    public UdpRequestProcessor(KeyMasterExecutor kmr, DatagramSocket socket) {
        super(kmr, new UdpLinkReceiver(socket), new UdpLinkSender(socket));
    }
}
