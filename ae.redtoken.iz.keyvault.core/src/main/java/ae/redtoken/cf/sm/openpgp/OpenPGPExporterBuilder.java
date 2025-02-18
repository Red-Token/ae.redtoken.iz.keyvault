package ae.redtoken.cf.sm.openpgp;

import ae.redtoken.cf.AbstractExporterBuilder;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
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
import java.util.Date;

import static org.bouncycastle.openpgp.PGPSignature.DEFAULT_CERTIFICATION;

public class OpenPGPExporterBuilder extends AbstractExporterBuilder<OpenPGPExporterBuilder> {

    protected String password;
    protected long creationTime;

    public OpenPGPExporterBuilder(KeyPair keyPair, Path root) {
        super(keyPair, root);
    }

    public OpenPGPExporterBuilder setPassword(String password) {
        this.password = password;
        return this;
    }

    public OpenPGPExporterBuilder setCreationTime(long creationTime) {
        this.creationTime = creationTime;
        return this;
    }

    private PGPSecretKey secretKey;

    public OpenPGPExporterBuilder build() {
        try {
            Date now = new Date(creationTime);

            // Create PGP Key Pair from RSA key pair
            JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, now);

            String id = String.format("%s <%s>", name, email);

            // Set up signature
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            this.secretKey = new PGPSecretKey(
                    DEFAULT_CERTIFICATION,
                    pgpKeyPair,
                    id,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(password.toCharArray())
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return this;
    }

    public class OpenPGPPublicKeyExporter extends AbstractExporter<OpenPGPPublicKeyExporter> {

        public OpenPGPPublicKeyExporter() {
            this.fileName = "public.asc";
        }

        public void export(final OutputStream stream) throws IOException {
            try {
                try (ArmoredOutputStream pubOut = new ArmoredOutputStream(stream)) {
                    secretKey.getPublicKey().encode(pubOut);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public class OpenPGPPrivateKeyExporter extends AbstractExporter<OpenPGPPrivateKeyExporter> {

        public OpenPGPPrivateKeyExporter() {
            this.fileName = "private.asc";
        }

        @Override
        public void export(final OutputStream stream) throws IOException {
            try {

                try (ArmoredOutputStream secOut = new ArmoredOutputStream(stream)) {
                    secretKey.encode(secOut);
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
    }
}
