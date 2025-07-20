package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMaster;

public class AvatarSpawnPoint {
    public KeyMasterAvatar connect(KeyMaster keyMaster) {
        return new KeyMasterAvatar(keyMaster);
    }
}
