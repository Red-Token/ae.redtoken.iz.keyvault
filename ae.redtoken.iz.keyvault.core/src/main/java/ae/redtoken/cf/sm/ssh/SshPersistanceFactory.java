package ae.redtoken.cf.sm.ssh;

import ae.redtoken.cf.AbstractKeyPersistanceFactory;
import net.schmizz.sshj.common.Buffer;
import se.h3.ca.PemHandler;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;

public class SshPersistanceFactory extends AbstractKeyPersistanceFactory {

    public SshPersistanceFactory(KeyPair keyPair, Path fileRoot) {
        super(keyPair, fileRoot.resolve("ssh"));
    }

    private String getAlg() {
        return "rsa";
    }

    private String getPublicKeyFileName() {
        return String.format("id_%s.pub", getAlg());
    }

    private String getPrivateKeyFileName() {
        return String.format("id_%s", getAlg());
    }


    @Override
    public void persistPublicKey() {
        try {
            final String keyAlg = getAlg();
            final OutputStream stream = new FileOutputStream(fileRoot.resolve(getPublicKeyFileName()).toFile());
            byte[] b = new Buffer.PlainBuffer().putPublicKey(keyPair.getPublic()).getCompactData();
            String s = String.format("ssh-%s %s %s", keyAlg, Base64.getEncoder().encodeToString(b), email);
            stream.write(s.getBytes(StandardCharsets.UTF_8));
            stream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public void persistPrivateKey(OutputStream stream, String password) {
        PemHandler.writeKey(new OutputStreamWriter(stream), keyPair.getPrivate());
    }
}
