package ae.redtoken.iz.keyvault.bitcoin.test;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatar;
import lombok.SneakyThrows;

abstract public class TestKeyMasterAvatarRunnable extends KeyMasterAvatar {

    public TestKeyMasterAvatarRunnable(KeyMasterRunnable keyMasterRunnable) {
        super(keyMasterRunnable);
    }

    @SneakyThrows
    public void runTest() {
    }
}
