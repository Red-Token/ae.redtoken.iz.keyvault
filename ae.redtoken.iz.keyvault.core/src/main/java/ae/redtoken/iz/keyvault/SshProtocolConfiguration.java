package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyProtocolMetaData;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.logging.Logger;

public class SshProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<SshProtocolConfiguration.SshProtocolCredentials> {
    private static final Logger log = Logger.getLogger(SshProtocolConfiguration.class.getName());

    static final String pcd = "ssh";

    static {
        Identity.protocolMap.put(pcd, SshProtocolConfiguration.class);
    }

    public SshProtocolConfiguration(Identity identity, ProtocolMetaData metaData) {
        super(identity, pcd, metaData);
    }

    public SshProtocolConfiguration(Identity identity, File file) {
        super(identity, pcd, file);
    }

    static final String FINGERPRINT_HASH_ALG = "SHA-256";

    @Override
    protected byte[] calculateFingerPrint(KeyPair kp) {
        try {
            AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(kp.getPublic().getEncoded());
            byte[] pubKeyData = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);
            byte[] digest = MessageDigest.getInstance(FINGERPRINT_HASH_ALG).digest(pubKeyData);
            log.info(String.format("Calculating fingerprint %s", Base64.getEncoder().encodeToString(digest)));
            return digest;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected SshProtocolCredentials createCredentials(KeyPair kp) {
        return new SshProtocolCredentials(kp);
    }

    public class SshProtocolCredentials extends AbstractImplementedPublicKeyCredentials {

        public SshProtocolCredentials(KeyPair kp) {
            super(kp);
        }

        protected String getPCD() {
            return pcd;
        }

        @Override
        protected ProtocolMetaData getMetaData() {
            return metaData;
        }

        @Override
        protected byte[] calculateFingerPrint() {
            return SshProtocolConfiguration.this.calculateFingerPrint(kp);
        }
    }
}
