package ae.redtoken.cf.sm.nostr;

import ae.redtoken.cf.AbstractExporterBuilder;
import nostr.base.PrivateKey;
import nostr.base.PublicKey;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

public class NostrExporterBuilder extends AbstractExporterBuilder<NostrExporterBuilder> {

    public NostrExporterBuilder(KeyPair keyPair, Path root) {
        super(keyPair, root);
    }

    public class NostrPublicKeyExporter extends AbstractExporter<NostrPublicKeyExporter> {

        public NostrPublicKeyExporter() {
            this.fileName = String.format("%s.npub", email);
        }

        public void export(final OutputStream stream) throws IOException {
            PublicKey pk = new PublicKey(getRawPublicKey((ECPrivateKey) keyPair.getPrivate()));
            stream.write(pk.toBech32String().getBytes(StandardCharsets.UTF_8));
        }
    }

    public class NostrPrivateKeyExporter extends AbstractExporter<NostrPrivateKeyExporter> {
        protected String password;

        public NostrPrivateKeyExporter() {
            this.fileName = String.format("%s.nsec", email);
        }

        public NostrPrivateKeyExporter setPassword(String password) {
            this.password = password;
            return this;
        }

        @Override
        public void export(final OutputStream stream) throws IOException {
            PrivateKey pk = new PrivateKey(getRawPrivateKey((ECPrivateKey) keyPair.getPrivate()));
            stream.write(pk.toBech32String().getBytes(StandardCharsets.UTF_8));
        }
    }

    private byte[] getRawPublicKey(ECPrivateKey privateKey) {
        try {
            return  Schnorr.genPubKey(getRawPrivateKey(privateKey));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] getRawPrivateKey(ECPrivateKey privateKey) {
        return NostrUtil.bytesFromBigInteger(privateKey.getS());
    }
}
