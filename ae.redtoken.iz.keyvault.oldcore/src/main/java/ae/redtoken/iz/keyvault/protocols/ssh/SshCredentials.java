package ae.redtoken.iz.keyvault.protocols.ssh;

import ae.redtoken.iz.keyvault.AbstractPublicKeyCredentials;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class SshCredentials extends AbstractPublicKeyCredentials<SshMetaData> {
    static Logger log = LoggerFactory.getLogger(SshCredentials.class);


    public SshCredentials(SecureRandom sr, SshMetaData metaData) {
        super(sr, metaData);
    }

    public SshCredentials(SecureRandom sr, File file) {
        super(sr, file);
    }

    @Override
    protected Class<SshMetaData> getMetaDataClass() {
        return SshMetaData.class;
    }

    static final String FINGERPRINT_HASH_ALG = "SHA-256";

    @Override
    protected byte[] calculateFingerPrint(KeyPair kp) {
        try {
            AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(kp.getPublic().getEncoded());
            byte[] pubKeyData = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);
            byte[] digest = MessageDigest.getInstance(FINGERPRINT_HASH_ALG).digest(pubKeyData);
            log.info("Calculating fingerprint {}", Base64.getEncoder().encodeToString(digest));
            return digest;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
