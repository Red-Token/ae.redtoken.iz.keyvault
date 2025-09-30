package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.IZSystemAvatar;
import ae.redtoken.iz.protocolls.ssh.agent.IZSshAgent;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.security.Security;

public class TestAvatar {

    @SneakyThrows
    @Test
    void testXXXX() {

//        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());

        String password = "Open Sesame!";
        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(AvatarSpawnPoint.SPAWN_PORT, password, AvatarSpawnPoint.SERVICE_PORT);

        IZSystemAvatar avatar = spawnPoint.spawn();

        IZSshAgent izSshAgent = new IZSshAgent(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT);

        // Do SSH command
        Process ps = Runtime.getRuntime().exec(new String[]{"ssh", "localhost", "exit"}, new String[]{"SSH_AUTH_SOCK=/tmp/zool.sock"});
        ps.waitFor();

        BufferedReader br = new BufferedReader(new InputStreamReader(ps.getInputStream()));
        br.lines().toList().forEach(System.out::println);
    }
}
