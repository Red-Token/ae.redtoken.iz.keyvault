package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import lombok.SneakyThrows;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.Arrays;

public class UdpLinkReceiver extends AbstractLinkReceiver<SocketAddress> {
    final byte[] buffer = new byte[AvatarSpawnPoint.MAX_PACKET_SIZE];
    final DatagramSocket socket;

    public UdpLinkReceiver(DatagramSocket socket) {
        this.socket = socket;
    }

    @SneakyThrows
    public byte[] receivePacket(RouteInfo<SocketAddress> routeInfo) {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        if (routeInfo != null) {
            routeInfo.route = packet.getSocketAddress();
        }

        return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
    }
}
