package ae.redtoken.iz.keyvault.protocols.openpgp;

import ae.redtoken.iz.keyvault.AbstractPublicKeyCredentials;
import ae.redtoken.util.Util;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.File;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

public class OpenPGPCredentials extends AbstractPublicKeyCredentials<OpenPGPMetaData> {
    public OpenPGPCredentials(SecureRandom sr, OpenPGPMetaData metaData) {
        super(sr, metaData);
    }

    public OpenPGPCredentials(SecureRandom sr, File file) {
        super(sr, file);
    }

    @Override
    public Class<OpenPGPMetaData> getMetaDataClass() {
        return OpenPGPMetaData.class;
    }

    @Override
    protected byte[] calculateFingerPrint(KeyPair keyPair) {
        return calculatePgpFingerPrint(keyPair, metaData.creationTime);
    }

    static byte[] calculatePgpFingerPrint(KeyPair kp, long creationTime) {
        try {
            // TODO FIX THIS
            if (!Objects.equals(kp.getPublic().getAlgorithm(), "RSA"))
                throw new RuntimeException("Algorithm not supported" + kp.getPublic().getAlgorithm());

            AsymmetricCipherKeyPair ackp = Util.convertJceToBcKeyPair(kp);
            PGPKeyPair bpkp = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, ackp, new Date(creationTime));

            return bpkp.getPublicKey().getFingerprint();

        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }

}
