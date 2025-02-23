package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyProtocolMetaData;
import org.blkzn.keymodules.gpg.BCOpenPGBConversionUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.File;
import java.security.KeyPair;
import java.util.Date;
import java.util.logging.Logger;

public class OpenPGPProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<OpenPGPProtocolConfiguration.OpenPGPProtocolCredentials> {
    private static final Logger log = Logger.getLogger(OpenPGPProtocolConfiguration.class.getName());

    public static final String pcd = "openpgp";

    static {
        Identity.protocolMap.put(pcd, OpenPGPProtocolConfiguration.class);
    }

    public OpenPGPProtocolConfiguration(Identity identity, ProtocolMetaData metaData) {
        super(identity, pcd, metaData);
    }

    public OpenPGPProtocolConfiguration(Identity identity, File file) {
        super(identity, pcd, file);
    }

    // TODO understand how the time works here right now we set it to 0

    @Override
    protected byte[] calculateFingerPrint(KeyPair kp) {
        return calculatePgpFingerPrint(kp, this.metaData.creationTime);
    }

    static byte[] calculatePgpFingerPrint(KeyPair kp, long creationTime) {
        try {
            AsymmetricCipherKeyPair ackp = BCOpenPGBConversionUtil.convertJceToBcKeyPair(kp);
            PGPKeyPair bpkp = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, ackp, new Date(creationTime));

            return bpkp.getPublicKey().getFingerprint();

        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected OpenPGPProtocolCredentials createCredentials(KeyPair kp) {
        return new OpenPGPProtocolCredentials(kp);
    }

    public void register(OpenPGPProtocolCredentials credentials) {
        throw new RuntimeException("Not implemented yet");
    }

    public class OpenPGPProtocolCredentials extends AbstractImplementedPublicKeyCredentials {
        public OpenPGPProtocolCredentials(KeyPair kp) {
            super(kp);
        }

        @Override
        protected String getPCD() {
            return OpenPGPProtocolConfiguration.pcd;
        }

        @Override
        protected ProtocolMetaData getMetaData() {
            return metaData;
        }

        @Override
        protected byte[] calculateFingerPrint() {
            return calculatePgpFingerPrint(kp, metaData.creationTime);
        }

//                private OpenPGPCertWizard openPGPCertWizard;
//
//                private void createFactory(String password) {
//                    openPGPCertWizard = new OpenPGPCertWizard(kp);
//                    openPGPCertWizard.setName(name);
//                    openPGPCertWizard.setEmail(id);
//                    openPGPCertWizard.setKeyGenerationTime(kgt);
//                    openPGPCertWizard.setPwd(password);
//                    openPGPCertWizard.create();
//                }

//                // TODO, this is not very very good we have a house of cards here make the model better
//                @Override
//                public void saveKeysToDir(File root, String password) {
//                    createFactory(password);
//                    openPGPCertWizard.save(root.toPath().resolve(pmd));
//                }

//                public String savePublicKeyToString() {
//                    //TODO This is ugly beyond comprehension there should be a way to split the factory in two
//                    if (openPGPCertWizard == null)
//                        createFactory("WhoCaresWeDontUseIt");
//
//                    ByteArrayOutputStream ba = new ByteArrayOutputStream();
//                    openPGPCertWizard.savePublicKeyRing(ba);
//                    return ba.toString();
//                }
//            }
//
//            public static final String pmd = "opgp";

//            private OpenPGPProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//                super(pmd, metaData);
//            }
//
//
//
//            public OpenPGPProtocolCredentials createAndRegisterNewCredentials() {
//                OpenPGPProtocolCredentials pc = new OpenPGPProtocolCredentials(kpg.genKeyPair(), System.currentTimeMillis());
//
//                byte[] hash = calculatePgpFingerPrint(pc.kp, pc.kgt);
//                DataSetOpenPGPMessage opgpMessage = new BlockZoneMessageFactory.DataSetGPGMessageBuilder()
//                        .setKeyAlg(metaData.pubAlg)
//                        .setKeySize(metaData.pubBits)
//                        .setHashAlg(metaData.hashAlg)
//                        .setHashSize(metaData.hashBits)
//                        .setKeyFlags(OpenPGPKeyFlags.PUBKEY_USAGE_SIG)
//                        .setKeyTime(pc.kgt)
//                        .setHash(hash)
//                        .build();
//
//                getController().publish(opgpMessage);
//                activeCredentials.add(pc);
//                return pc;
//            }
//
//            public void restoreKey(OpenPGPMessageElement gme, long maxTries) {
//
//                for (int i = 0; i < maxTries; i++) {
//                    KeyPair candidate = this.kpg.genKeyPair();
//                    byte[] ch = calculatePgpFingerPrint(candidate, gme.kt.getValue());
//
//                    if (Arrays.equals(gme.hash.getValue(), ch)) {
//                        activeCredentials.add(new OpenPGPProtocolCredentials(candidate, gme.kt.getValue()));
//                        log.info("Key restored");
//                        return;
//                    }
//                }
//
//                throw new RuntimeException("No key found");
    }
}
