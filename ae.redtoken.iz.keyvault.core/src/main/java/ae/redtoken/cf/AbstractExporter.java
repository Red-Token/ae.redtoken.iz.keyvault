package ae.redtoken.cf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

abstract public class AbstractExporter {
    private static final Logger log
            = LoggerFactory.getLogger(AbstractExporter.class);

    public static final Map<String, String> algMap = new HashMap<>();

    static {
        algMap.put("RSA", "rsa");
        algMap.put("DSA", "dsa");
        algMap.put("Ed25519", "ed25519");
        algMap.put("EdDSA", "eddsa");
    }

    @FunctionalInterface
    private interface WriteToFile {
        void apply(OutputStream stream) throws IOException;
    }

    protected final KeyPair keyPair;
    protected final Path root;

    public AbstractExporter(KeyPair keyPair, Path fileRoot) {
        this.keyPair = keyPair;
        this.root = fileRoot;
    }

    public void exportPublicKey() {
        try {
            export(this::exportPublicKey, getPublicKeyFileName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void exportPrivateKey() {
        try {
            export(this::exportPrivateKey, getPrivateKeyFileName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract String getPublicKeyFileName();

    protected abstract String getPrivateKeyFileName();

    protected abstract void exportPublicKey(OutputStream stream) throws IOException;

    protected abstract void exportPrivateKey(OutputStream stream) throws IOException;

    protected String getAlg() {
        log.trace(keyPair.getPublic().getAlgorithm());
        return algMap.get(keyPair.getPrivate().getAlgorithm());
    }

    private void createRoot() {
        if (root.toFile().mkdirs()) {
            log.debug("Created root directory: {}", root);
        }
    }

    private void export(WriteToFile function, String fileName) {
        try {
            createRoot();
            final OutputStream stream = new FileOutputStream(root.resolve(fileName).toFile());
            function.apply(stream);
            stream.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
