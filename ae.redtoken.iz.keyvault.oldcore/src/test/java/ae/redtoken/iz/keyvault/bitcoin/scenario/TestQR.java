package ae.redtoken.iz.keyvault.bitcoin.scenario;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.FileSystems;
import java.util.Enumeration;

import static ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint.createQR;

public class TestQR {


    @SneakyThrows
    @Test
    void testQR() {

        LoginInfo loginInfo = new LoginInfo();

        loginInfo.address = "192.168.100.14";
        loginInfo.port = AvatarSpawnPoint.SPAWN_PORT;
        loginInfo.password = "Open Sesame!";

        String path = "qr_code.png";           // Output file
        createQR(loginInfo, FileSystems.getDefault().getPath(path));
    }

    @SneakyThrows
    @Test
    void testIP() {

        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            for (InetAddress addr : iface.inetAddresses().toList()) {
                System.out.println(addr.getHostAddress());
            }
        }
    }
}
