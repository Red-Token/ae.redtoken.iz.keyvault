package ae.redtoken.iz.keyvault.bitcoin.scenario;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.IZSystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.protocolls.ssh.agent.IZSshAgent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;

public class TestAvatar {



    @SneakyThrows
    @Test
    void testStartAvatar() {
        Security.addProvider(new BouncyCastleProvider());

        String password = "Open Sesame!";
        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(AvatarSpawnPoint.SPAWN_PORT, password, AvatarSpawnPoint.SERVICE_PORT);

        LoginInfo loginInfo = new LoginInfo();
        loginInfo.address = "192.168.100.14";
        loginInfo.port = AvatarSpawnPoint.SPAWN_PORT;
        loginInfo.password = password;

        AvatarSpawnPoint.createQR(loginInfo, Path.of("/tmp/avatar.png"));

        IZSystemAvatar avatar = spawnPoint.spawn();

        IZSshAgent izSshAgent = new IZSshAgent(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT);

        // Save the ssh key
        String email = "bob@teahouse.wl";
        String alg = SshKeyType.ED25519.sshName;
        String keyString = String.format("%s %s %s", alg, izSshAgent.sshGetPublicKeyAccept.pubKey(), email);
        System.out.println(keyString);

        FileOutputStream stream = new FileOutputStream(Path.of("/tmp/zool.pub").toFile());
        stream.write(keyString.getBytes(StandardCharsets.UTF_8));


//        // Do SSH command
//        Process ps = Runtime.getRuntime().exec(new String[]{"ssh", "localhost", "ls"}, new String[]{"SSH_AUTH_SOCK=/tmp/zool.sock"});
//        ps.waitFor();
//
//        Assertions.assertEquals(0, ps.exitValue());
//
//        BufferedReader br = new BufferedReader(new InputStreamReader(ps.getInputStream()));
//        br.lines().toList().forEach(System.out::println);

        while (true) {
            Thread.sleep(1000);
        }
    }
}
