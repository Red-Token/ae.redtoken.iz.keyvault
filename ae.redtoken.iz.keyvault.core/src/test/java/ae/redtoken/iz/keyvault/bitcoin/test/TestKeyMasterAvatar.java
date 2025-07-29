package ae.redtoken.iz.keyvault.bitcoin.test;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnectior;
import lombok.SneakyThrows;

abstract public class TestKeyMasterAvatar extends KeyMasterAvatarConnectior {

    public TestKeyMasterAvatar(KeyMasterRunnable keyMasterRunnable) {
        super(keyMasterRunnable);
    }

    @SneakyThrows
    public void runTest() {
    }
}
