package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;

public class AvatarSpawnPoint {
    public KeyMasterAvatar connect(KeyMasterRunnable keyMaster) {
        return new KeyMasterAvatar(keyMaster);
    }
}
