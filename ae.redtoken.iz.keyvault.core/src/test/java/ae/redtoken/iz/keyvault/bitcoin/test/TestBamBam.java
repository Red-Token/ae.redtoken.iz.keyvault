package ae.redtoken.iz.keyvault.bitcoin.test;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnectior;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class TestBamBam {

    static class AvatarSpawnPoint implements Runnable {
        static final int AVATAR_PORT = 10000;
        DatagramSocket socket;
        boolean run = true;
        BlockingQueue<KeyMasterAvatarConnectior> avatar = new LinkedBlockingQueue<>(1);

        @SneakyThrows
        public AvatarSpawnPoint() {
            this.socket = new DatagramSocket(AVATAR_PORT);
        }

        @SneakyThrows
        @Override
        public void run() {
            while (run) {
                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                System.out.println(new String(packet.getData(), 0, packet.getLength()));
            }

        }
    }

    @SneakyThrows
    @Test
    void name() {

        int port = 10000;

        Thread t = new Thread(() -> {
            try {
                // This is the Avatar waiting for a connection
                DatagramSocket socket = new DatagramSocket(port);

                while (true) {
                    byte[] buffer = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    byte[] buffer2 = "Zool is cool".getBytes();
                    DatagramPacket reply = new DatagramPacket(buffer2, buffer2.length, packet.getAddress(), packet.getPort());
                    socket.send(reply);

                    System.out.println(new String(packet.getData(), 0, packet.getLength()));
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        t.start();

        String message = "Hello, UDP Server!";
        InetAddress address = InetAddress.getByName("localhost");
        byte[] buffer = message.getBytes();

        DatagramSocket socket = new DatagramSocket();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, port);

        byte[] buffer2 = new byte[1024];
        DatagramPacket reply = new DatagramPacket(buffer2, buffer2.length);

        socket.send(packet);
        socket.receive(reply);
        System.out.println("Message sent: " + message);
        System.out.println(new String(reply.getData(), 0, reply.getLength()));
    }
}
