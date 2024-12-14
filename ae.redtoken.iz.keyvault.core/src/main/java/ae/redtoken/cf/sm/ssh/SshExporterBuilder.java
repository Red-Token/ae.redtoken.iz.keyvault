package ae.redtoken.cf.sm.ssh;

import ae.redtoken.cf.AbstractExporterBuilder;

import ae.redtoken.util.PemHandler;
import net.schmizz.sshj.common.Buffer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SshExporterBuilder extends AbstractExporterBuilder<SshExporterBuilder> {
    static final Map<String,String> algMap = new HashMap<>();
    static {
        algMap.put("RSA", "rsa");
    }

    public SshExporterBuilder(KeyPair keyPair, Path root) {
        super(keyPair, root);
    }

    public class SshPublicKeyExporter extends AbstractExporter<SshPublicKeyExporter> {

        public SshPublicKeyExporter() {
            this.fileName = String.format("id_%s.pub", getAlg());
        }

        @Override
        protected void export(OutputStream stream) throws IOException {
            byte[] b = new Buffer.PlainBuffer().putPublicKey(keyPair.getPublic()).getCompactData();
            String s = String.format("ssh-%s %s %s", getAlg(), Base64.getEncoder().encodeToString(b), email);
            stream.write(s.getBytes(StandardCharsets.UTF_8));
        }
    }
    public class SshPrivateKeyExporter extends AbstractExporter<SshPrivateKeyExporter> {
        protected String password;

        public SshPrivateKeyExporter() {
            this.fileName = String.format("id_%s", getAlg());
        }

        public SshPrivateKeyExporter setPassword(String password) {
            this.password = password;
            return this;
        }

        @Override
        protected void export(OutputStream stream) throws IOException {
                PemHandler.writeKey(new OutputStreamWriter(stream), keyPair.getPrivate());
        }
    }

    private String getAlg() {
        return algMap.get(keyPair.getPrivate().getAlgorithm());
    }
}
