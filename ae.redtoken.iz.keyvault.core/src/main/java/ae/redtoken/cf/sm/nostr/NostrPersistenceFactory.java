package ae.redtoken.cf.sm.nostr;

import ae.redtoken.cf.AbstractKeyPersistanceFactory;

import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;

public class NostrPersistenceFactory extends AbstractKeyPersistanceFactory {

    public NostrPersistenceFactory(KeyPair keyPair, Path fileRoot) {
        super(keyPair, fileRoot);
    }

    protected String getDefaultPublicKeyFileName() {
        return "nostr.npub";
    }

    @Override
    public void persistPublicKey() {
    }

    @Override
    public void persistPrivateKey(OutputStream stream, String password) {
    }
}
