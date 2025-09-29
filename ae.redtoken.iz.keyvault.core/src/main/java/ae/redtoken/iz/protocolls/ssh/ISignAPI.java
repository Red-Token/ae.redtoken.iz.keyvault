package ae.redtoken.iz.protocolls.ssh;

import java.security.PublicKey;

public interface ISignAPI {
    PublicKey getPublicKey();

    byte[] sign(byte[] key, byte[] data);
}
