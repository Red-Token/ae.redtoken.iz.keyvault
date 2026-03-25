package ae.redtoken.cf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

abstract public class AbstractAsymmetricalExporter extends AbstractExporter {
    private static final Logger log
            = LoggerFactory.getLogger(AbstractAsymmetricalExporter.class);

    public static final Map<String, String> algMap = new HashMap<>();

    static {
        algMap.put("RSA", "rsa");
        algMap.put("DSA", "dsa");
        algMap.put("Ed25519", "ed25519");
        algMap.put("EdDSA", "eddsa");
    }

    protected final KeyPair keyPair;

    public AbstractAsymmetricalExporter(KeyPair keyPair, Path fileRoot, boolean forceOverWrite) {
        super(fileRoot, forceOverWrite);
        this.keyPair = keyPair;
    }

    public void exportPublicKey() {
        export(this::exportPublicKey, getPublicKeyFileName());
    }

    public void exportPrivateKey() {
        export(this::exportPrivateKey, getPrivateKeyFileName());
    }

    protected abstract String getPublicKeyFileName();

    protected abstract String getPrivateKeyFileName();

    protected abstract void exportPublicKey(OutputStream stream) throws IOException;

    protected abstract void exportPrivateKey(OutputStream stream) throws IOException;

    protected String getAlg() {
        log.trace(keyPair.getPublic().getAlgorithm());
        return algMap.get(keyPair.getPrivate().getAlgorithm());
    }
}
