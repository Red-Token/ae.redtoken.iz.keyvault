package ae.redtoken.iz.keyvault.bitcoin.scenario;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.IZSystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.protocolls.ssh.agent.IZSshAgent;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;

public class TestAvatar2 {



    @SneakyThrows
    @Test
    void testStartAvatar() {
        Security.addProvider(new BouncyCastleProvider());

        String password = "Open Sesame!";

        LoginInfo loginInfo = new LoginInfo();
        loginInfo.address = "192.168.2.234";
        loginInfo.port = AvatarSpawnPoint.SPAWN_PORT;
        loginInfo.password = password;

        AvatarSpawnPoint.createQR(loginInfo, Path.of("/tmp/avatar.png"));
    }
}
