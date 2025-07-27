package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import lombok.SneakyThrows;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AvatarSpawnPoint {
    public final static String HOSTNAME = "localhost";
    public final static int PORT = 10000;

    DatagramSocket socket;
    final String password;

    @SneakyThrows
    public AvatarSpawnPoint(String password) {
        this.socket = new DatagramSocket(PORT, InetAddress.getByName(HOSTNAME));
        this.password = password;
    }

    //    public KeyMasterAvatar connect(KeyMasterRunnable keyMaster) {
//        return new KeyMasterAvatar(keyMaster);
//    }
    @SneakyThrows
    public KeyMasterAvatar spawn() {
        BlockingQueue<KeyMasterAvatar> queue = new LinkedBlockingQueue<>(1);

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

                    KeyMasterAvatar avatar = new KeyMasterAvatar(socket, packet.getSocketAddress());
                    queue.offer(avatar);
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
