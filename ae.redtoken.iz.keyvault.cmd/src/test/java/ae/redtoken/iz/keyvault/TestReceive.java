package ae.redtoken.iz.keyvault;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class TestReceive {

    @SneakyThrows
    @Test
    void name() {


        DatagramSocket socket = new DatagramSocket(15000);

        DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);

        socket.receive(packet);

        System.out.println(new String(packet.getData()));


    }
}
