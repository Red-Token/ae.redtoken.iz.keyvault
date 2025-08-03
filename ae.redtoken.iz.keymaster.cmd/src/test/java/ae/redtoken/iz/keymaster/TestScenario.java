package ae.redtoken.iz.keymaster;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

public class TestScenario {


    @SneakyThrows
    @Test
    void testAvatarAndKeyMastetr() {
        Thread testAvatar = new Thread(() -> KeyMasterMain.main(new String[]{"avatar", "start"}));
        testAvatar.start();

        Thread.sleep(1000);

        Thread testKeyMaster = new Thread(() -> KeyMasterMain.main(new String[]{"keymaster", "start", "--config-root", "/var/tmp/iz-keymaster/id/"}));
        testKeyMaster.start();

        testAvatar.join();
    }
}
