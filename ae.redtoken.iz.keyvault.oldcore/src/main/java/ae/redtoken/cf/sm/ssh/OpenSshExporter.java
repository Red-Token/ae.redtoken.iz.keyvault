package ae.redtoken.cf.sm.ssh;

import ae.redtoken.cf.AbstractAsymmetricalExporter;
import ae.redtoken.util.PemHandler;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Objects;

public class OpenSshExporter extends AbstractAsymmetricalExporter {
    private final String email;

    public OpenSshExporter(KeyPair keyPair, Path root, String email,  boolean forceOverWrite) {
        super(keyPair, root, forceOverWrite);
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
    protected String getAlg() {
        String algStr = super.getAlg();

        if (Objects.equals(algStr, "eddsa")) {
            algStr = "ed25519";
        }

        return algStr;
    }

    @Override
    protected void exportPublicKey(OutputStream stream) throws IOException {
        AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(keyPair.getPublic().getEncoded());
        byte[] b = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);
        String s = String.format("ssh-%s %s %s", getAlg(), Base64.getEncoder().encodeToString(b), email);
        System.out.println(s);
        stream.write(s.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void exportPrivateKey(OutputStream stream) throws IOException {
        AsymmetricKeyParameter privateKeyParams;
        privateKeyParams = PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded()));
        byte[] bytes = OpenSSHPrivateKeyUtil.encodePrivateKey(privateKeyParams);
        PemHandler.writePem(new OutputStreamWriter(stream), "OPENSSH PRIVATE KEY", bytes);
    }
}
