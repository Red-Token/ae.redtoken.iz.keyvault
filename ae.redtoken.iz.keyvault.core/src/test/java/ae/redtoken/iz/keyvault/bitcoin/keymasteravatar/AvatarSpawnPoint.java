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
    final LoginManager loginManager;
    final Thread loginThread;

    @SneakyThrows
    public AvatarSpawnPoint(String password) {
        this.socket = new DatagramSocket(PORT, InetAddress.getByName(HOSTNAME));
        this.password = password;
        this.loginManager = new LoginManager();
        this.loginThread = new Thread(this.loginManager);
        this.loginThread.start();
    }

    class LoginManager implements Runnable {
        BlockingQueue<SystemAvatar> queue = new LinkedBlockingQueue<>(1);

        @SneakyThrows
        @Override
        public void run() {
            while (true) {
                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                if (!password.equals(new String(Arrays.copyOfRange(packet.getData(), 0, packet.getLength())))) {
                    System.out.println("Rejected");
                    continue;
                }

                socket.connect(packet.getAddress(), packet.getPort());
                queue.put(new SystemAvatar(socket));
                return;
            }
        }
    }

    @SneakyThrows
    public SystemAvatar spawn() {
        return loginManager.queue.take();
    }
}
