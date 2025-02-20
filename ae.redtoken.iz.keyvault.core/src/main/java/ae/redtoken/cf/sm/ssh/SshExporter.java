package ae.redtoken.cf.sm.ssh;

import ae.redtoken.cf.AbstractExporter;
import ae.redtoken.util.PemHandler;
import net.schmizz.sshj.common.Buffer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;

public class SshExporter extends AbstractExporter {
    private final String email;

    public SshExporter(KeyPair keyPair, Path root, String email) {
        super(keyPair, root);
        this.email = email;
    }

    @Override
    protected String getPublicKeyFileName() {
        return String.format("id_%s.pub", getAlg());
    }

    @Override
    protected String getPrivateKeyFileName() {
        return String.format("id_%s", getAlg());
    }

    @Override
    protected void exportPublicKey(OutputStream stream) throws IOException {
        byte[] b = new Buffer.PlainBuffer().putPublicKey(keyPair.getPublic()).getCompactData();
        String s = String.format("ssh-%s %s %s", getAlg(), Base64.getEncoder().encodeToString(b), email);
        stream.write(s.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void exportPrivateKey(OutputStream stream) throws IOException {
        PemHandler.writeKey(new OutputStreamWriter(stream), keyPair.getPrivate());
    }
}
