package ae.redtoken.iz.keyvault.bitcoin.test;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Avatar;
import lombok.SneakyThrows;

abstract public class TestKeyMasterAvatarRunnable extends Avatar<KeyMasterStackedService> {
    @SneakyThrows
    public void runTest() {
    }
}
