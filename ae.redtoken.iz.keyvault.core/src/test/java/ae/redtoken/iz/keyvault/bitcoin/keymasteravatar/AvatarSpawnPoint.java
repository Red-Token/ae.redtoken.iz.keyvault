package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;

public class AvatarSpawnPoint {
    public KeyMasterAvatar connect(KeyMasterStackedService keyMaster) {
        return new KeyMasterAvatar(keyMaster);
    }
}
