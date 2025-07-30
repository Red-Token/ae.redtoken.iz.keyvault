package ae.redtoken.iz.keyvault.bitcoin.test;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector;
import lombok.SneakyThrows;

abstract public class TestKeyMasterAvatar extends KeyMasterAvatarConnector {

    public TestKeyMasterAvatar(KeyMasterExecutor keyMasterRunnable) {
        super(keyMasterRunnable);
    }

    @SneakyThrows
    public void runTest() {
    }
}
