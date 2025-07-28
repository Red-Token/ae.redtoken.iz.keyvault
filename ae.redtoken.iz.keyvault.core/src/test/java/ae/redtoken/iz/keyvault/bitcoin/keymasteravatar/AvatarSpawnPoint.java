package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import lombok.SneakyThrows;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AvatarSpawnPoint {
    public final static String HOSTNAME = "localhost";
    public final static int PORT = 10000;
    public final static int SERVICE_PORT = 10001;
    public final static int MAX_PACKET_SIZE = 1024;

    DatagramSocket socket;
    final String password;


    @SneakyThrows
    public AvatarSpawnPoint(String password) {
        this.socket = new DatagramSocket(PORT, InetAddress.getByName(HOSTNAME));
        this.password = password;
    }

    @SneakyThrows
    public Azur spawn() {
        BlockingQueue<Azur> queue = new LinkedBlockingQueue<>(1);

        Thread thread = new Thread(() -> {
            try {
                boolean spawned = false;
                boolean running = true;

                while (!spawned) {
                    byte[] buffer = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    if (!password.equals(new String(Arrays.copyOfRange(packet.getData(), 0, packet.getLength())))) {
                        continue;
                    }

                    socket.connect(packet.getAddress(), packet.getPort());
                    Azur azur = new Azur(socket);
                    queue.offer(azur);
                    spawned = true;
                }


            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        thread.start();

        return queue.take();
    }

}
