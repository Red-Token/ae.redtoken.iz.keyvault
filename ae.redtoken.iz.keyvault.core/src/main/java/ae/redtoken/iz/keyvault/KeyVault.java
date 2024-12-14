package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.KeyVault.Identity.AbstractPublicKeyProtocolConfiguration.AbstractImplementedPublicKeyCredentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.schmizz.sshj.common.Buffer;
import nostr.base.PrivateKey;
import nostr.base.PublicKey;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bitcoinj.wallet.DeterministicSeed;
import org.blkzn.client.BlkZnClient;
import org.blkzn.controll.IGranter;
import org.blkzn.controll.UserController;
import org.blkzn.controll.ZoneController;
import org.blkzn.msg.BlockZoneMessageFactory;
import org.blkzn.msg.dataset.DataSetSSHMessage;
import org.blkzn.name.UserName;
import org.blkzn.stack.BlkZnEntity;
import org.blkzn.stack.Registration;
import org.blkzn.wallet.AbstractPublicKeyCredentials;
import org.blkzn.wallet.IGrantFinder;
import org.blkzn.wallet.PublicKeyProtocolMetaData;
import org.blkzn.wallet.WalletHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.h3.ca.Constants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static ae.redtoken.util.Util.assertDirectoryExists;
import static ae.redtoken.util.Util.parsePersistentData;

/**
 * A blockzone (user) wallet contains a master-seed TODO: rename master-seed to steurer seed)
 * that in turn generate a subset of identity seeds, these identity seeds would then in turn generate protocol seeds.
 * It also connects a blkzn client, that has a btc wallet connected to it. The blkzn client in tur then generate a UserController (ZoneController or ServiceController) That controls
 * the relevant entity. So there is one blkzn client per wallet, and it supports controlling multiple entities with its controllers. TODO: The BlkZn Wallet should be renamed
 */
public class KeyVault {
    private static final Logger log
            = LoggerFactory.getLogger(KeyVault.class);
    static final int SEED_SIZE = 32;

    private BlkZnClient mclient;

    public BlkZnClient getClient() {
        if (mclient == null) {
            this.mclient = new BlkZnClient(WalletHelper.createSubSeed(this.seed, "#blkzn").getSeedBytes());
        }

        return mclient;
    }


    public void saveMnemonicWordsToFile(File seedFile) {
        WalletHelper.writeMnemonicWordsToFile(seed, seedFile);
    }

    public Identity restoreIdentity(String id, String name) {
        Identity identity = new Identity(id, name);
//        identity.uc = client.client.getUserController(id);

        identity.restoreAll();
        return identity;
    }

    public Identity createIdentity(String idString, String name) {
        return new Identity(idString, name);
    }

    public Identity registerIdentity(Identity identity, IGrantFinder grantFinder) {
        UserName un = new UserName(identity.id);
        IGranter granter = grantFinder.getGranter(un.getParent());
        // TODO a lot of ugly hardcodes here!
        identity.getController().register(10000, granter, 1, 10);
        return identity;
    }

    final DeterministicSeed seed;

    abstract public class AbstractEntity {
        final protected String id;
        final DeterministicSeed seed;

        protected AbstractEntity(String id) {
            this.id = id;
            this.seed = WalletHelper.createSubSeed(KeyVault.this.seed, id);
        }
    }

    public class Zone extends AbstractEntity {
        final public ZoneController zc;

        public Zone(String id) {
            super(id);
            this.zc = getClient().getZoneController(id);
        }
    }

    public class Identity extends AbstractEntity {
//        final public UserController uvc;

        public UserController getController() {
            return getClient().getUserController(id);
        }

        public SshProtocolConfiguration createSshKeyConfiguration(String pubAlg, int pubBits, String hashAlg, int hashBits) {
            return new SshProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
        }

        public NostrProtocolConfiguration createNostrKeyConfiguration() {
            return new NostrProtocolConfiguration(new PublicKeyProtocolMetaData());
        }

//        public SSHProtocolConfiguration registerSshKey(String pubAlg, int pubBits, String hashAlg, int hashBits) {
//            return new SSHProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
//        }


        /**
         * PublicKeyProtocolConfiguration contains a specific configuration for a given protocol, this includes data like key_alg and key_size.
         *
         * @param <T>
         */
        public abstract class AbstractPublicKeyProtocolConfiguration<T extends AbstractImplementedPublicKeyCredentials> {
            private static int DEFAULT_MAX_TRY_COUNT = 1000;

            abstract protected byte[] calculateFingerPrint(KeyPair kp);

            abstract protected T createCredentials(KeyPair kp);

            public void restoreKey(byte[] hash) {
                restoreKey(hash, DEFAULT_MAX_TRY_COUNT);
            }

            public void restoreKey(byte[] hash, long maxTries) {
                log.info("looking for key: {}", NostrUtil.bytesToHex(hash));

                for (int i = 0; i < maxTries; i++) {
                    KeyPair candidate = kpg.genKeyPair();
                    byte[] ch = calculateFingerPrint(candidate);

                    log.info("generated key: {}", NostrUtil.bytesToHex(ch));

                    if (Arrays.equals(hash, ch)) {
                        activeCredentials.add(createCredentials(candidate));
                        log.info("Key restored");
                        return;
                    }
                }

                throw new RuntimeException("No key found");
            }

            abstract class AbstractImplementedPublicKeyCredentials extends AbstractPublicKeyCredentials {
                public AbstractImplementedPublicKeyCredentials(KeyPair kp) {
                    super(kp);
                }

                @Override
                final public void saveKeysToDir(File file, String s) {
                    throw new UnsupportedOperationException("Not implemented");
                }

                abstract protected String getPCD();

                abstract protected PublicKeyProtocolMetaData getMetaData();

//                protected byte[] calculateFingerPrint() throws IOException {
//                    return AbstractPublicKeyProtocolConfiguration.this.calculateFingerPrint(this.kp);
//                }

                protected String getDefaultFileName() {
                    return "defaultKeyCredentials.json";
                }

                public void persist(Path path) {
                    persist(path.resolve(getPCD()).resolve(getDefaultFileName()).toFile());
                }

                public void persist(File file) {
                    try {
                        ObjectMapper om = new ObjectMapper();
                        assertDirectoryExists(file.getParentFile());
                        om.writeValue(file, new PublicKeyPersistentData(getMetaData(), calculateFingerPrint(kp)));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            final PublicKeyProtocolMetaData metaData;
            final DeterministicSeed seed;
            final SecureRandom sr;
            final KeyPairGenerator kpg;
            final public Collection<T> activeCredentials = new ArrayList<>();

            public AbstractPublicKeyProtocolConfiguration(String pmd, PublicKeyProtocolMetaData metaData) {
                this.metaData = metaData;

                if (Identity.this.protocolCredentials.containsKey(pmd))
                    throw new RuntimeException("You cant do this!");

                this.seed = WalletHelper.createSubSeed(Identity.this.seed, pmd);

                log.info("Created subseed {} for id {}", NostrUtil.bytesToHex(Objects.requireNonNull(this.seed.getSeedBytes())), pmd);

                this.sr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);

                this.kpg = createKeyPairGenerator();
                Identity.this.protocolCredentials.put(pmd, this);
            }

            private AbstractPublicKeyProtocolConfiguration(String pcd, PublicKeyPersistentData keyPersistentData) {
                this(pcd, keyPersistentData.metaData);
                restoreKey(keyPersistentData.fingerprint);
            }

            AbstractPublicKeyProtocolConfiguration(String pcd, File file) {
                this(pcd, parsePersistentData(file, PublicKeyPersistentData.class));
            }

            //TODO Make this nicer
            protected KeyPairGenerator createKeyPairGenerator() {
                try {
                    Constants javaConstants = getJavaConstants();
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(javaConstants.getAsym());
                    kpg.initialize(javaConstants.getKeysize(), sr);

                    return kpg;
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            protected Constants getJavaConstants() {
                // TODO this is a hack!
                return new Constants(
                        this.metaData.pubBits,
                        this.metaData.pubAlg.name().toUpperCase(),
                        //"SHA256withRSA"
                        String.format("%s%dwith%s",
                                metaData.hashAlg.name().toUpperCase(),
                                metaData.hashBits,
                                metaData.pubAlg.name().toUpperCase()),
                        //"SHA-256"
                        String.format("%s-%d",
                                metaData.hashAlg.name().toUpperCase(),
                                metaData.hashBits)
                );
            }
        }

//        public OpenPGPProtocolConfiguration registerPGPkey(String pubAlg, int pubBits, String hashAlg, int hashBits) {
//            return new OpenPGPProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
//        }

//        public OpenPGPProtocolConfiguration restorePgpProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//            return new OpenPGPProtocolConfiguration(metaData);
//        }

//        public X509ProtocolConfiguration registerX509Key(String pubAlg, int pubBits, String hashAlg, int hashBits) {
//            return new X509ProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
//        }
//
//        public X509ProtocolConfiguration restoreX509ProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//            return new X509ProtocolConfiguration(metaData);
//        }

        static final Map<String, Class<? extends AbstractPublicKeyProtocolConfiguration<? extends AbstractImplementedPublicKeyCredentials>>> protocolMap = new HashMap<>();

        public class SshProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<SshProtocolConfiguration.SshProtocolCredentials> {
            static final String pcd = "ssh";
            static {
                protocolMap.put(pcd, SshProtocolConfiguration.class);
            }

            private SshProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
                super(pcd, metaData);
            }

            SshProtocolConfiguration(File file) {
                super(pcd, file);
            }

            public void restore(File file) {
                try {
                    ObjectMapper om = new ObjectMapper();
                    PublicKeyPersistentData pd = om.readValue(file, PublicKeyPersistentData.class);
                    restoreKey(pd.fingerprint);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

//            private void restoreKey(byte[] fingerprint, int defaultMaxTryCount) {
//            }


            public SshProtocolCredentials create() {
                SshProtocolCredentials pc = new SshProtocolCredentials(kpg.genKeyPair());
                activeCredentials.add(pc);
//                register(pc);
                return pc;
            }

            /**
             * Saves the public key
             *
             * @param pc
             */
            public void save(SshProtocolCredentials pc) {
//                pc.saveKeysToDir();
            }

            public void savePrivate(SshProtocolCredentials pc) {
            }

            public void register(SshProtocolCredentials pc) {
                byte[] hash = calculateFingerPrint(pc.kp);
                DataSetSSHMessage sshMessage = new BlockZoneMessageFactory.DataSetSSHMessageBuilder()
                        .setKeyAlg(metaData.pubAlg)
                        .setKeySize(metaData.pubBits)
                        .setHashAlg(metaData.hashAlg)
                        .setHashSize(metaData.hashBits)
                        .setHash(hash)
                        .build();

                getController().publish(sshMessage);
            }

            static final String FINGERPRINT_HASH_ALG = "SHA-256";

            @Override
            protected byte[] calculateFingerPrint(KeyPair kp) {
                try {
                    byte[] pubKeyData = new Buffer.PlainBuffer().putPublicKey(kp.getPublic()).getCompactData();
                    return MessageDigest.getInstance(FINGERPRINT_HASH_ALG).digest(pubKeyData);
                } catch (NoSuchAlgorithmException e) {
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
                protected PublicKeyProtocolMetaData getMetaData() {
                    return metaData;
                }
            }
        }

//        /**
//         * This is ZoolCool!
//         * <p>
//         * If no domain CA is configured on the domain the default procedure is to create a self-signed CA, and sign the id yourself
//         * Since this is a self-signed CA, it should be fully verifiable using the blockchain. So any blkzn aware TLS implementation should
//         * be able to fully verify this cert. However, if a DomainCA is configured then the key should be sent out to be signed.
//         * The self-signed version should be fully restorable from the info in the blockchain.
//         */
//        public class X509ProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<X509ProtocolConfiguration.X509ProtocolCredentials> {
//            public static final String pmd = "x509";
//
//            public void restoreKey(X509MessageElement xme, long maxTries) {
//
//                for (int i = 0; i < maxTries; i++) {
//                    X509ProtocolCredentials candidate = new X509ProtocolCredentials(this.kpg.genKeyPair());
//
//                    if (Arrays.equals(xme.hash.getValue(), candidate.calculateX509SubjectKeyIdentifier())) {
////                        candidate.setCertificate(register(candidate.getRequestString()));
//                        activeCredentials.add(candidate);
//                        log.info("Key restored");
//                        return;
//                    }
//                }
//
//                throw new RuntimeException("No key found");
//            }
//
//            public class X509ProtocolCredentials extends AbstractPublicKeyCredentials {
//
//                X509Certificate certificate;
//
//                public X509ProtocolCredentials(KeyPair kp) {
//                    super(kp);
//                }
//
//                public byte[] calculateX509SubjectKeyIdentifier() {
//                    try {
//                        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
//                        PublicKey publicKey = kp.getPublic();
//
//                        byte[] keyBytes = publicKey.getEncoded();
//
//                        if (publicKey instanceof RSAPublicKey) {
//                            // For RSA public keys, extract the modulus bytes
//                            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
//                            keyBytes = rsaPublicKey.getModulus().toByteArray();
//                        }
//
//                        // Calculate the SHA-1 hash of the key bytes
//                        byte[] hashBytes = sha1.digest(keyBytes);
//
//                        // The first 20 bytes of the hash represent the SKI
//                        return Arrays.copyOf(hashBytes, 20);
//                    } catch (NoSuchAlgorithmException e) {
//                        throw new RuntimeException(e);
//                    }
//                }
//
//
//                public PKCS10CertificationRequest getRequest() {
//                    final X509CertificationRequestWizard wizard;
//                    wizard = new X509CertificationRequestWizard(kp);
//                    wizard.setName(name);
//                    wizard.setEmail(id);
//                    wizard.create();
//
//                    return wizard.request;
//                }
//
//                public void setCertificate(String certificate) {
//                    this.certificate = PemHandler.readCert(certificate);
//                }
//
//                @Override
//                public void saveKeysToDir(File idRoot, String password) {
//                    Path moduleRoot = idRoot.toPath().resolve(pmd);
//                    Util.assurePathExists(moduleRoot);
//                    savePrivateKey(moduleRoot);
//                    savePublicKey(moduleRoot);
////                    savePKCS10CertificationRequest(moduleRoot);
////                    saveX509Certificate(moduleRoot);
//                }
//
//                public void saveCertificate(File idRoot) {
//                    Path moduleRoot = idRoot.toPath().resolve(pmd);
//                    Util.assurePathExists(moduleRoot);
//                    saveX509Certificate(moduleRoot);
//                }
//
//                private void savePrivateKey(Path moduleRoot) {
//                    PemHandler.writeKey(moduleRoot.resolve(id + ".key.pem").toFile(), kp.getPrivate());
//                }
//
//                private void savePublicKey(Path moduleRoot) {
//                    PemHandler.writePublicKey(moduleRoot.resolve(id + ".pub.pem").toFile(), kp.getPublic());
//                }
//
//                private void savePKCS10CertificationRequest(Path moduleRoot) {
//                    PemHandler.writeReq(moduleRoot.resolve(id + ".csr.pem").toFile(), getRequest());
//                }
//
//                private void saveX509Certificate(Path moduleRoot) {
//                    if (certificate == null)
//                        return;
//
//                    PemHandler.writeCert(moduleRoot.resolve(id + ".crt.pem").toFile(), certificate);
//                }
//            }
//
//            private X509ProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//                super(pmd, metaData);
//            }
//
//            boolean selfSign = true;
//
//            String register(PKCS10CertificationRequest req) {
//                IDomainCA ca = new SillyCA(caRoot, domain);
//                return ca.register(PemHandler.toPEMString(req));
//            }
//
//            public X509ProtocolCredentials createAndRegisterNewCredentials() {
//                // Create a new set of credentials
//                X509ProtocolCredentials pc = new X509ProtocolCredentials(kpg.genKeyPair());
//
//                byte[] hash = pc.calculateX509SubjectKeyIdentifier();
//                DataSetX509Message x509Message = new BlockZoneMessageFactory.DataSetX509MessageBuilder()
//                        .setKeyAlg(metaData.pubAlg)
//                        .setKeySize(metaData.pubBits)
//                        .setHashAlg(metaData.hashAlg)
//                        .setHashSize(metaData.hashBits)
////                        .setKeyFlags(OpenPGPKeyFlags.PUBKEY_USAGE_SIG)
////                        .setKeyTime(pc.kgt)
//                        .setHash(hash)
//                        .build();
//
//                getController().publish(x509Message);
//

        /// /                pc.setCertificate(register(pc.getRequestString()));
//
//                activeCredentials.add(pc);
//                return pc;
//            }
//        }

        public class NostrProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<NostrProtocolConfiguration.NostrProtocolCredentials> {
            public static final String pcd = "nostr";

            static {
                protocolMap.put(pcd, NostrProtocolConfiguration.class);
            }

            public NostrProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
                super(pcd, metaData);
            }

            public NostrProtocolConfiguration(File file) {
                super(pcd, file);
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

            @Override
            protected byte[] calculateFingerPrint(KeyPair kp) {
                return getRawPublicKey((ECPrivateKey) kp.getPrivate());
            }

            @Override
            protected NostrProtocolCredentials createCredentials(KeyPair kp) {
                return new NostrProtocolCredentials(kp);
            }

            @Override
            protected KeyPairGenerator createKeyPairGenerator() {
                try {

                    Security.addProvider(new BouncyCastleProvider());
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
                    kpg.initialize(new ECGenParameterSpec("secp256k1"), sr);
                    return kpg;

                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }
            }

//            public static byte[] generatePrivateKey() {
//                try {
//

            /// /                    Constants javaConstants = getJavaConstants();
            /// /                    this.kpg = KeyPairGenerator.getInstance(javaConstants.getAsym());
            /// /                    this.kpg.initialize(javaConstants.getKeysize(), sr);
//
//
//                    Security.addProvider(new BouncyCastleProvider());
//                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
//                    kpg.initialize(new ECGenParameterSpec("secp256k1"), SecureRandom.getInstanceStrong());
//                    KeyPair processorKeyPair = kpg.genKeyPair();
//                    return NostrUtil.bytesFromBigInteger(((ECPrivateKey) processorKeyPair.getPrivate()).getS());
//                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException var2) {
//                    GeneralSecurityException e = var2;
//                    throw new RuntimeException(e);
//                }
//            }
            public NostrProtocolCredentials create() {
                return new NostrProtocolCredentials(kpg.genKeyPair());
            }

            public void register(NostrProtocolCredentials npc) {
            }

            public class NostrProtocolCredentials extends AbstractImplementedPublicKeyCredentials {
                String DEFAULT_KEY_DATA = "zool.json";

                public NostrProtocolCredentials(KeyPair kp) {
                    super(kp);
                }

                @Override
                protected String getPCD() {
                    return NostrProtocolConfiguration.pcd;
                }

                @Override
                protected PublicKeyProtocolMetaData getMetaData() {
                    return null;
                }

                public void persist(Path path) {
                    try {
                        File file = path.resolve(NostrProtocolConfiguration.pcd).resolve(DEFAULT_KEY_DATA).toFile();
                        assertDirectoryExists(file.getParentFile());
                        ObjectMapper om = new ObjectMapper();
                        om.writeValue(file, new PublicKeyPersistentData(NostrProtocolConfiguration.this.metaData, calculateFingerPrint(kp)));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

//        public class OpenPGPProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<OpenPGPProtocolConfiguration.OpenPGPProtocolCredentials> {
//
//            public boolean loadKey() {
//                return true;
//            }
//
//            public class OpenPGPProtocolCredentials extends AbstractPublicKeyCredentials {
//                public final long kgt;
//
//                public OpenPGPProtocolCredentials(KeyPair kp, long kgt) {
//                    super(kp);
//                    this.kgt = kgt;
//                }
//
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
//
//                // TODO, this is not very very good we have a house of cards here make the model better
//                @Override
//                public void saveKeysToDir(File root, String password) {
//                    createFactory(password);
//                    openPGPCertWizard.save(root.toPath().resolve(pmd));
//                }
//
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
//
//            private OpenPGPProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//                super(pmd, metaData);
//            }
//
//            static byte[] calculatePgpFingerPrint(KeyPair kp, long creationTime) {
//                try {
//                    AsymmetricCipherKeyPair ackp = BCOpenPGBConversionUtil.convertJceToBcKeyPair(kp);
//                    PGPKeyPair bpkp = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, ackp, new Date(creationTime));
//
//                    return bpkp.getPublicKey().getFingerprint();
//
//                } catch (PGPException e) {
//                    throw new RuntimeException(e);
//                }
//            }
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
//            }
//        }

        final String name;

        public Identity(String id, String name) {
            super(id);
            this.name = name;
//            this.uvc = getClient().getUserController(id);
        }

        public void loadAll() {
            BlkZnEntity blkZnEntity = getController().getBlkZnEntity();
            Registration registration = blkZnEntity.getActiveRegistration();

            if (registration == null) {
                log.warn("FIXME: Trying to restore while registration is null we could have a unclean directory here");
                return;
            }

//            registration.opgp.forEach(gme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(gme);
//                OpenPGPProtocolConfiguration openPGPProtocolConfiguration =
//                        restorePgpProtocolConfiguration(metaData);
//                openPGPProtocolConfiguration.loadKey();
////                openPGPProtocolConfiguration.restoreKey(gme, 1000);
//            });
        }

        private void recallProtocol(File protocolDir) throws Exception {

            Constructor<?>[] declaredConstructors = protocolMap.get(protocolDir.getName()).getDeclaredConstructors();

            Constructor<? extends AbstractPublicKeyProtocolConfiguration<? extends AbstractPublicKeyCredentials>> constructor
                    = protocolMap.get(protocolDir.getName()).getDeclaredConstructor(Identity.class, File.class);

            Arrays.stream(Objects.requireNonNull(protocolDir.listFiles()))
                    .filter(file -> file.getName().endsWith(".json"))
                    .forEach(file -> {
                                try {
                                    constructor.newInstance(this, file);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }
                    );

            System.out.println("SFSFSDF");
        }

        void recallAll(Path idPath) {
            File idDir = idPath.toFile();

            if (!idDir.exists() || !idDir.isDirectory()) {
                log.warn("Path does not exist or is not a directory");
                return;
            }

            Arrays.stream(Objects.requireNonNull(idDir.listFiles()))
                    .filter(file -> protocolMap.containsKey(file.getName()))
                    .forEach(file -> {
                                try {
                                    recallProtocol(file);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }
                    );
        }

        void restoreAll() {
            BlkZnEntity blkZnEntity = getController().getBlkZnEntity();
            Registration registration = blkZnEntity.getActiveRegistration();

            if (registration == null) {
                log.warn("FIXME: Trying to restore while registration is null we could have a unclean directory here");
                return;
            }

//            registration.opgp.forEach(gme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(gme);
//                OpenPGPProtocolConfiguration openPGPProtocolConfiguration =
//                        restorePgpProtocolConfiguration(metaData);
//                openPGPProtocolConfiguration.restoreKey(gme, 1000);
//            });

//            registration.ssh.forEach(sme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(sme);
//                SSHProtocolConfiguration sshProtocolConfiguration =
//                        new SSHProtocolConfiguration(metaData);
//                sshProtocolConfiguration.restoreKey(sme.hash.getValue(), 1000);
//            });

//            registration.x509.forEach(xme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(xme);
//                X509ProtocolConfiguration x509ProtocolConfiguration =
//                        new X509ProtocolConfiguration(metaData);
//                x509ProtocolConfiguration.restoreKey(xme, 1000);
//            });

        }

        public Map<String, AbstractPublicKeyProtocolConfiguration<? extends AbstractPublicKeyCredentials>> protocolCredentials = new HashMap<>();
    }

//    protected final IGrantFinder gf;

    protected KeyVault(DeterministicSeed seed) {
        this.seed = seed;

        // TODO: have this checked
        // Now we create the subseed for blkzn using a fixed string.
    }

    public static KeyVault fromRandomSeed() {
        return new KeyVault(WalletHelper.generateDeterministicSeed(SEED_SIZE));
    }

    public static KeyVault fromSeedFile(File seedFile) {
        return new KeyVault(WalletHelper.readMnemonicWordsFromFile(seedFile));
    }
}
