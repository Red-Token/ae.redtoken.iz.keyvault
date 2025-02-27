package ae.redtoken.cf.sm.openpgp;

import ae.redtoken.cf.AbstractExporter;
import lombok.SneakyThrows;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

import static org.bouncycastle.openpgp.PGPSignature.DEFAULT_CERTIFICATION;

public class OpenPGPExporter extends AbstractExporter {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final PGPSecretKey secretKey;

    @SneakyThrows
    public OpenPGPExporter(KeyPair keyPair, Path root, String name, String email, String password, long creationTime, boolean forceOverWrite) {
        super(keyPair, root, forceOverWrite);

        // Create PGP Key Pair from RSA key pair
        JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, new Date(creationTime));

        // Set up signature
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        this.secretKey = new PGPSecretKey(
                DEFAULT_CERTIFICATION,
                pgpKeyPair,
                String.format("%s <%s>", name, email),
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(
                        pgpKeyPair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(
                        PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(password.toCharArray())
        );
    }

    @Override
    protected String getPublicKeyFileName() {
        return "public.asc";
    }

    @Override
    protected String getPrivateKeyFileName() {
        return "private.asc";
    }

    @Override
    protected void exportPublicKey(OutputStream stream) throws IOException {
        try (ArmoredOutputStream pubOut = new ArmoredOutputStream(stream)) {
            secretKey.getPublicKey().encode(pubOut);
        }
    }

    @Override
    protected void exportPrivateKey(OutputStream stream) throws IOException {
        try (ArmoredOutputStream secOut = new ArmoredOutputStream(stream)) {
            secretKey.encode(secOut);
        }
    }
}
