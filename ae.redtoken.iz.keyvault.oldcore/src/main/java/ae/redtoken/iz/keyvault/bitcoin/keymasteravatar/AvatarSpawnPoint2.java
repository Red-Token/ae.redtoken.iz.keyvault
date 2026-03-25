package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.AbstractLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrOverUdpReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrRoute;
import ae.redtoken.iz.keyvault.bitcoin.scenario.LoginInfo2;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.event.impl.GenericEvent;
import nostr.id.Identity;

import java.io.IOException;
import java.net.DatagramSocket;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

@Slf4j
public class AvatarSpawnPoint2 {
    @SneakyThrows
    public static void createQR(LoginInfo2 loginInfo, Path path) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        String data = mapper.writeValueAsString(loginInfo);
        int width = 300;
        int height = 300;

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, width, height);

        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);

        System.out.println("QR Code generated at: " + path);
    }


    public final static String HOSTNAME = "localhost";
    public final static int SPAWN_PORT = 10000;
    public final static int SERVICE_PORT = 10001;
    public final static int MAX_PACKET_SIZE = 1024;
    public final static String DEFAULT_PASSWORD = "OpenSeamy";
    private final int servicePort;

    DatagramSocket socket;
    final LoginManager loginManager;
    public final Thread loginThread;
    public final Identity identity = Identity.generateRandomIdentity();

    @SneakyThrows
    public AvatarSpawnPoint2(int spawnPort, int servicePort) {

        this.socket = new DatagramSocket(spawnPort);
        this.servicePort = servicePort;
        this.loginManager = new LoginManager();
        this.loginThread = new Thread(this.loginManager);
        this.loginThread.start();
    }

    class LoginManager implements Runnable {
        BlockingQueue<IZSystemAvatar2> queue = new LinkedBlockingQueue<>(1);

        @SneakyThrows
        @Override
        public void run() {
            while (true) {

                NostrOverUdpReceiver nour = new NostrOverUdpReceiver(socket);

                AbstractLinkReceiver.RouteInfo<NostrRoute> route = new AbstractLinkReceiver.RouteInfo<>();
                GenericEvent event = nour.receiveEvent(route);

                socket.connect(route.route.socketAddress);
//
//                byte[] buffer = new byte[1024];
//                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
//                socket.receive(packet);
//                String pubkeyHex = new String(Arrays.copyOf(packet.getData(), packet.getLength()));
//                log.atInfo().log(pubkeyHex);
//                PublicKey publicKey = new PublicKey(pubkeyHex);
//                socket.connect(packet.getAddress(), packet.getPort());
                queue.put(new IZSystemAvatar2(socket, identity, event.getPubKey(), servicePort));
                return;
            }
        }
    }

    @SneakyThrows
    public IZSystemAvatar2 spawn() {
        return loginManager.queue.take();
    }
}
