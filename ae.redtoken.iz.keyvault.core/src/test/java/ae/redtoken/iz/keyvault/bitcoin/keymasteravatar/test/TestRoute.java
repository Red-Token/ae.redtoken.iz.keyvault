package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.test;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.AbstractLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.UdpLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.UdpLinkSender;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;

public class TestRoute {

    @SneakyThrows
    @Test
    void testRM() {

        DatagramSocket socket = new DatagramSocket(10000);
        DatagramSocket senderSocket = new DatagramSocket();
        final byte[] data = "Hello".getBytes(StandardCharsets.UTF_8);


        Thread t = new Thread(new Runnable() {

            @SneakyThrows
            @Override
            public void run() {
                UdpLinkReceiver receiver = new UdpLinkReceiver(socket);
               AbstractLinkReceiver.RouteInfo<SocketAddress> info = new AbstractLinkReceiver.RouteInfo<>();
                byte[] receivePacket = receiver.receivePacket(info);

                Assertions.assertEquals(senderSocket.getLocalPort(), ((InetSocketAddress) info.route).getPort());
                Assertions.assertArrayEquals(data, receivePacket);
            }
        });
        t.start();

        UdpLinkSender sender = new UdpLinkSender(senderSocket);
        sender.sendPacket(data, socket.getLocalSocketAddress());
        t.join();
    }
}
