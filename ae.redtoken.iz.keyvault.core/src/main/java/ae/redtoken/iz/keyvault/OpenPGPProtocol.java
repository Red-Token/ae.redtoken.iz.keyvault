package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocolls.AbstractCredentialsMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import org.blkzn.keymodules.gpg.BCOpenPGBConversionUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

public class OpenPGPProtocol extends AbstractPublicKeyProtocol<OpenPGPProtocol.OpenPGPCredentialsMetaData, OpenPGPProtocol.OpenPGPCredentials> {
    static Logger log = LoggerFactory.getLogger(OpenPGPProtocol.class);

    public static final String pcd = "openpgp";

    static {
        Identity.protocolMap.put(pcd, OpenPGPProtocol.class);
    }

    // This will be called when we create
    public OpenPGPProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public OpenPGPProtocol(Identity identity, Path idPath) {
        super(identity, idPath);
    }


    @Override
    protected Class<OpenPGPCredentials> getCredentialClass() {
        return OpenPGPCredentials.class;
    }

    @Override
    protected String getProtocolName() {
        return pcd;
    }

    public static class OpenPGPCredentialsMetaData extends AbstractCredentialsMetaData {
        public long creationTime;

        public OpenPGPCredentialsMetaData(PublicKeyProtocolMetaData publicKeyMetadata, long creationTime) {
            super(publicKeyMetadata);
            this.creationTime = creationTime;
        }

        public OpenPGPCredentialsMetaData() {
            super();
        }
    }

    public static class OpenPGPCredentials extends AbstractPublicKeyCredentials<OpenPGPCredentialsMetaData> {
        protected OpenPGPCredentials(SecureRandom sr, OpenPGPCredentialsMetaData metaData) {
            super(sr, metaData);
        }

        protected OpenPGPCredentials(SecureRandom sr, File file) {
            super(sr, file);
        }

        @Override
        public Class<OpenPGPCredentialsMetaData> getMetaDataClass() {
            return OpenPGPCredentialsMetaData.class;
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

                AsymmetricCipherKeyPair ackp = BCOpenPGBConversionUtil.convertJceToBcKeyPair(kp);
                PGPKeyPair bpkp = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, ackp, new Date(creationTime));

                return bpkp.getPublicKey().getFingerprint();

            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }

    }
}
