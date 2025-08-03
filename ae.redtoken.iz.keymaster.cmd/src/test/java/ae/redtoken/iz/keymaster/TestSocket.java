package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.UdpRequestProcessor;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

public class TestSocket {

    @SneakyThrows
    @Test
    void testSocket() {

        final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SPAWN_PORT);
        final DatagramSocket socket = new DatagramSocket();
        socket.connect(avatarSocketAddress);

        String passphrase = "Open Sesame!";

        Thread t = new Thread(() -> {
            try {
                Thread.sleep(1000);

                //Log in
                DatagramPacket packet = new DatagramPacket(passphrase.getBytes(), passphrase.length());
                socket.send(packet);

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        t.start();

        Thread.sleep(2000);
    }


}
