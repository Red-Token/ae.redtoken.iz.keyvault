package ae.redtoken.cf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;

abstract public class AbstractKeyPersistanceFactory {
    private static final Logger log
            = LoggerFactory.getLogger(AbstractKeyPersistanceFactory.class);

    protected final KeyPair keyPair;

    protected String name;
    protected String email;

    public Path fileRoot;

    public AbstractKeyPersistanceFactory(KeyPair keyPair, Path fileRoot) {
        this.keyPair = keyPair;
        this.fileRoot = fileRoot;
    }

    void createRoot() {
        if(fileRoot.toFile().mkdirs()) {
            log.debug("Created root directory: {}", fileRoot);
        }
    }

    // Saves the public key in the root
    abstract public void persistPublicKey();
    abstract public void persistPrivateKey(OutputStream stream, String password);

    public AbstractKeyPersistanceFactory setName(String name) {
        this.name = name;
        return this;
    }

    public AbstractKeyPersistanceFactory setEmail(String email) {
        this.email = email;
        return this;
    }
}
