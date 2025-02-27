package ae.redtoken.cf;

import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

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

    private final boolean forceOverWrite;

    @FunctionalInterface
    private interface WriteToFile {
        void apply(OutputStream stream) throws IOException;
    }

    protected final KeyPair keyPair;
    protected final Path root;

    public AbstractExporter(KeyPair keyPair, Path fileRoot, boolean forceOverWrite) {
        this.forceOverWrite = forceOverWrite;
        this.keyPair = keyPair;
        this.root = fileRoot;
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

    private void createRoot() {
        if (root.toFile().mkdirs()) {
            log.debug("Created root directory: {}", root);
        }
    }

    @SneakyThrows
    private void export(WriteToFile function, String fileName) {
        createRoot();
        final File file = root.resolve(fileName).toFile();

        if (file.exists() && !forceOverWrite) {
            log.error("File already exists: {}", file);
            throw new IOException("File already exists: " + file);
        }

        final OutputStream stream = new FileOutputStream(file);
        function.apply(stream);
        stream.close();

        log.info("Exported file: {}", file);
    }
}
