package ae.redtoken.cf;

import ae.redtoken.cf.sm.ssh.SshExporterBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;

abstract public class AbstractExporterBuilder<B extends AbstractExporterBuilder<B>> {
    private static final Logger log
            = LoggerFactory.getLogger(AbstractExporterBuilder.class);

    abstract public class AbstractExporter<T extends AbstractExporter<T>> {
        protected String fileName;

        public AbstractExporter() {
        }

        @SuppressWarnings("unchecked")
        T setFileName(String fileName) {
            this.fileName = fileName;
            return (T) this;
        }

        final public void export() {
            try {

                final OutputStream stream = new FileOutputStream(root.resolve(this.fileName).toFile());
                export(stream);
                stream.close();

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        abstract protected void export(final OutputStream stream) throws IOException;
    }

    protected final KeyPair keyPair;
    protected final Path root;

    protected String name;
    protected String email;

    public AbstractExporterBuilder(KeyPair keyPair, Path fileRoot) {
        this.keyPair = keyPair;
        this.root = fileRoot;
    }

    void createRoot() {
        if (root.toFile().mkdirs()) {
            log.debug("Created root directory: {}", root);
        }
    }

    @SuppressWarnings("unchecked")
    public B setName(String name) {
        this.name = name;
        return (B) this;
    }

    @SuppressWarnings("unchecked")
    public B setEmail(String email) {
        this.email = email;
        return (B) this;
    }
}
