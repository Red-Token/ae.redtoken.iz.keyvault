package ae.redtoken.iz.keyvault.bitcoin.ssh;

import java.security.PublicKey;

public interface ISignAPI {
    PublicKey getPublicKey();

    byte[] sign(byte[] key, byte[] data);
}
