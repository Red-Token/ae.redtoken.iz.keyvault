package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Azur {
    // reply coming from the keymaster
    final DatagramSocket upperSocket;

    // request coming from the user
    final DatagramSocket lowerSocket;
    private final boolean run = true;
    Map<Integer, SocketAddress> paths = new HashMap<>();


    abstract static class LinkService implements Runnable {
        static ObjectMapper mapper = new ObjectMapper();

        abstract static class AbstractLinkReceiver {
            abstract byte[] receivePacket();
        }

        static class UdpLinkReceiver extends AbstractLinkReceiver {
            final byte[] buffer = new byte[AvatarSpawnPoint.MAX_PACKET_SIZE];
            final DatagramSocket socket;

            UdpLinkReceiver(DatagramSocket socket) {
                this.socket = socket;
            }

            @SneakyThrows
            @Override
            byte[] receivePacket() {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
            }
        }

        abstract static class AbstractLinkSender<R> {
            abstract public void sendPacket(byte[] packet);
            abstract public void sendPacket(byte[] packet, R route);
        }

        static class UdpLinkSender extends AbstractLinkSender<SocketAddress> {
            final DatagramSocket socket;

            UdpLinkSender(DatagramSocket socket) {
                this.socket = socket;
            }

            @SneakyThrows
            public void sendPacket(byte[] packet) {
                socket.send(new DatagramPacket(packet, packet.length));
            }

            @SneakyThrows
            public void sendPacket(byte[] packet, SocketAddress socketAddress) {
                socket.send(new DatagramPacket(packet, packet.length, socketAddress));
            }
        }

        static class MessageSender<A, R> {
            final AbstractLinkSender<R> sender;

            MessageSender(AbstractLinkSender<R> sender) {
                this.sender = sender;
            }

            @SneakyThrows
            private byte[] pack(A message) {
                return mapper.writeValueAsBytes(message);
            }

            @SneakyThrows
            void sendMessage(A message) {
                sender.sendPacket(pack(message));
            }

            @SneakyThrows
            void sendMessage(A message, R route) {
                sender.sendPacket(pack(message), route);
            }
        }

        static class ResponseSender<R> extends MessageSender<Response, R> {
            ResponseSender(AbstractLinkSender<R> sender) {
                super(sender);
            }
        }

        static class MessageReceiver<A> {
            final AbstractLinkReceiver receiver;
            final Class<A> cls;

            MessageReceiver(AbstractLinkReceiver receiver, Class<A> cls) {
                this.receiver = receiver;
                this.cls = cls;
            }

            @SneakyThrows
            A receive() {
                byte[] receivedData = receiver.receivePacket();
                System.out.println("AZUR Works req");

                return mapper.readValue(receivedData, cls);
            }
        }

        static class RequestReceiver extends MessageReceiver<Request> {
            RequestReceiver(AbstractLinkReceiver receiver) {
                super(receiver, Request.class);
            }
        }

        static class ResponseReceiver extends MessageReceiver<Response> {
            ResponseReceiver(AbstractLinkReceiver receiver) {
                super(receiver, Response.class);
            }
        }
    }

    /**
     * class the handles traffic from the uplink
     */
    class UpLinkService extends LinkService {
        ResponseReceiver responseReceiver = new ResponseReceiver(new UdpLinkReceiver(upperSocket));
        ResponseSender<SocketAddress> responseSender = new ResponseSender<>(new UdpLinkSender(lowerSocket));

        @SneakyThrows
        @Override
        public void run() {

            while (run) {
                Response response = responseReceiver.receive();

                SocketAddress sa = paths.remove(response.id());

                if (sa == null) {
                    throw new RuntimeException("Could not find socket address");
                }

                responseSender.sendMessage(response, sa);
            }
        }
    }

    /**
     * class that handles traffic from  the downlink
     */
    class DownLinkService extends LinkService {

        @Override
        public void run() {

        }
    }


    @SneakyThrows
    public Azur(DatagramSocket upperSocket) {
        this.upperSocket = upperSocket;
        this.lowerSocket = new DatagramSocket(AvatarSpawnPoint.SERVICE_PORT);


        // Messages coming from the user to the master
        Thread upLinkService = new Thread(new UpLinkService());
        upLinkService.start();

        // Reply coming from the keymaster
        Thread downLinkService = new Thread(() -> {
            try {
                while (run) {
                    byte[] buffer = new byte[AvatarSpawnPoint.MAX_PACKET_SIZE];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    lowerSocket.receive(packet);

                    System.out.println("AZUR Works resp");

                    ObjectMapper objectMapper = new ObjectMapper();
                    byte[] receivedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
                    Request request = objectMapper.readValue(receivedData, Request.class);
                    paths.put(request.id(), packet.getSocketAddress());
                    upperSocket.send(new DatagramPacket(receivedData, receivedData.length));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        downLinkService.start();
    }
}
