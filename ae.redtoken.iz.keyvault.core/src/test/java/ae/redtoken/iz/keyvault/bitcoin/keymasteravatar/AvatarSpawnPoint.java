package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterService;

public class AvatarSpawnPoint {
    public KeyMasterAvatar connect(KeyMasterService keyMaster) {
        return new KeyMasterAvatar(keyMaster);
    }
}
