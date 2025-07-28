package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.checkerframework.checker.units.qual.A;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AvatarSpawnPoint {
    public final static String HOSTNAME = "localhost";
    public final static int PORT = 10000;
    public final static int SERVICE_PORT = 10001;
    public final static int PACKET_SIZE = 1024;

    DatagramSocket socket;
    DatagramSocket socket2;

    final String password;


    public static class Azur {
        // reply coming from the keymaster
        final DatagramSocket upperSocket;

        // request coming from the user
        final DatagramSocket lowerSocket;
        private final boolean run = true;


        @SneakyThrows
        public Azur(DatagramSocket upperSocket) {
            this.upperSocket = upperSocket;
            this.lowerSocket = new DatagramSocket(SERVICE_PORT);

            Map<Integer, SocketAddress> paths = new HashMap<>();


            // Messages coming from the user to the master
            Thread upLinkService = new Thread(() -> {
                try {
                    while (run) {
                        byte[] buffer = new byte[PACKET_SIZE];
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                        upperSocket.receive(packet);

                        System.out.println("AZUR Works req");

                        ObjectMapper objectMapper = new ObjectMapper();
                        byte[] receivedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
                        Response response = objectMapper.readValue(receivedData, Response.class);
                        SocketAddress sa = paths.remove(response.id());
                        lowerSocket.send(new DatagramPacket(receivedData,receivedData.length, sa));
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            upLinkService.start();

            // Reply coming from the keymaster
            Thread downLinkService = new Thread(() -> {
                try {
                    while (run) {
                        byte[] buffer = new byte[PACKET_SIZE];
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                        lowerSocket.receive(packet);

                        System.out.println("AZUR Works resp");

                        ObjectMapper objectMapper = new ObjectMapper();
                        byte[] receivedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
                        Request request = objectMapper.readValue(receivedData, Request.class);
                        paths.put(request.id(), packet.getSocketAddress());
                        upperSocket.send(new DatagramPacket(receivedData,receivedData.length));
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            downLinkService.start();
        }
    }


    @SneakyThrows
    public AvatarSpawnPoint(String password) {
        this.socket = new DatagramSocket(PORT, InetAddress.getByName(HOSTNAME));
        this.password = password;
    }

    //    public KeyMasterAvatar connect(KeyMasterRunnable keyMaster) {
//        return new KeyMasterAvatar(keyMaster);
//    }
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

//                    KeyMasterAvatar avatar = new KeyMasterAvatar(socket, packet.getSocketAddress());
//                    queue.offer(avatar);
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
