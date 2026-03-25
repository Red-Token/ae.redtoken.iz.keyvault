package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.IZSystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.protocolls.ssh.agent.IZSshAgent;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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

        // Save the ssh key
        String email = "bob@teahouse.wl";
        String alg = SshKeyType.ED25519.sshName;
        String keyString = String.format("%s %s %s", alg, izSshAgent.sshGetPublicKeyAccept.pubKey(), email);
        System.out.println(keyString);

        FileOutputStream stream = new FileOutputStream(Path.of("/tmp/zool.pub").toFile());
        stream.write(keyString.getBytes(StandardCharsets.UTF_8));


        // Do SSH command
        Process ps = Runtime.getRuntime().exec(new String[]{"ssh", "localhost", "ls"}, new String[]{"SSH_AUTH_SOCK=/tmp/zool.sock"});
        ps.waitFor();

        Assertions.assertEquals(0, ps.exitValue());

        BufferedReader br = new BufferedReader(new InputStreamReader(ps.getInputStream()));
        br.lines().toList().forEach(System.out::println);

        while (true) {
            Thread.sleep(1000);
        }
    }
}
