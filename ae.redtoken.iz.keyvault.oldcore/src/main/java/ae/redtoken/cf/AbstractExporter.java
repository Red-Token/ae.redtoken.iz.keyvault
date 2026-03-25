package ae.redtoken.cf;

import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
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

    protected void export(WriteToFile function, String fileName) {
        createRoot();
        final File file = root.resolve(fileName).toFile();

        if (file.exists() && !forceOverWrite) {
            log.error("File already exists: {}", file);
            throw new RuntimeException(new IOException("File already exists: " + file));
        }

        final OutputStream stream;

        try {
            stream = new FileOutputStream(file);
            function.apply(stream);
            stream.close();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        log.info("Exported file: {}", file);
    }
}
