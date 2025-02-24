package ae.redtoken.cf.sm.nostr;

import ae.redtoken.cf.AbstractExporter;
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

public class NostrExporter extends AbstractExporter {

    private final String email;

    public NostrExporter(KeyPair keyPair, Path root, String email) {
        super(keyPair, root);
        this.email = email;
    }

    @Override
    protected String getPublicKeyFileName() {
        return String.format("%s.npub", email);
    }

    @Override
    protected String getPrivateKeyFileName() {
        return String.format("%s.nsec", email);
    }

    @Override
    protected void exportPublicKey(OutputStream stream) throws IOException {
        PublicKey pk = new PublicKey(getRawPublicKey((ECPrivateKey) keyPair.getPrivate()));
        stream.write(pk.toBech32String().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void exportPrivateKey(OutputStream stream) throws IOException {
        PrivateKey pk = new PrivateKey(getRawPrivateKey((ECPrivateKey) keyPair.getPrivate()));
        stream.write(pk.toBech32String().getBytes(StandardCharsets.UTF_8));
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
