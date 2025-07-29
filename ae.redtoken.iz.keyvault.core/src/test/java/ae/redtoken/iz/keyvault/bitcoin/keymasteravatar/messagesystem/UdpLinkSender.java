package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import lombok.SneakyThrows;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;

public class UdpLinkSender extends AbstractLinkSender<SocketAddress> {
    final DatagramSocket socket;

    public UdpLinkSender(DatagramSocket socket) {
        this.socket = socket;
    }


    @SneakyThrows
    public void sendPacket(byte[] packet, SocketAddress socketAddress) {
        socket.send(new DatagramPacket(packet, packet.length, socketAddress == null ? socket.getRemoteSocketAddress() : socketAddress));
    }
}
