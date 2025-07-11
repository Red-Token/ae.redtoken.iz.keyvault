package ae.redtoken.cf;

import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

public class AbstractExporter {
    private static final Logger log
            = LoggerFactory.getLogger(AbstractExporter.class);

    protected final Path root;
    private final boolean forceOverWrite;

    @FunctionalInterface
    protected interface WriteToFile {
        void apply(OutputStream stream) throws IOException;
    }

    public AbstractExporter(Path root, boolean forceOverWrite) {
        this.root = root;
        this.forceOverWrite = forceOverWrite;

    }

    private void createRoot() {
        if (root.toFile().mkdirs()) {
            log.debug("Created root directory: {}", root);
        }
    }

    @SneakyThrows
    protected void export(WriteToFile function, String fileName) {
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
