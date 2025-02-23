package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyAlg;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import ae.redtoken.util.WalletHelper;
import nostr.util.NostrUtil;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Logger;

import static ae.redtoken.util.Util.parsePersistentData;

/**
 * PublicKeyProtocolConfiguration contains a specific configuration for a given protocol, this includes data like key_alg and key_size.
 *
 * @param <T>
 */
public abstract class AbstractPublicKeyProtocolConfiguration<T extends AbstractImplementedPublicKeyCredentials> {
    private static final Logger log = Logger.getLogger(AbstractPublicKeyProtocolConfiguration.class.getName());

    private static final int DEFAULT_MAX_TRY_COUNT = 1000;
    private final Identity identity;

    abstract protected byte[] calculateFingerPrint(KeyPair kp);

    abstract protected T createCredentials(KeyPair kp);

    public void restoreKey(byte[] hash) {
        restoreKey(hash, DEFAULT_MAX_TRY_COUNT);
    }

    public void restoreKey(byte[] hash, long maxTries) {
        log.info("looking for key: " + Base64.getEncoder().encodeToString(hash));

        for (int i = 0; i < maxTries; i++) {
            KeyPair candidate = kpg.genKeyPair();
            byte[] ch = calculateFingerPrint(candidate);
            log.info("generated key: " + NostrUtil.bytesToHex(ch));

            if (Arrays.equals(hash, ch)) {
                activeCredentials.add(createCredentials(candidate));
                log.info("Key restored");
                return;
            }
        }

        throw new RuntimeException("No key found");
    }

    public final T create() {
        KeyPair keyPair = kpg.genKeyPair();
        T pc = createCredentials(keyPair);
        activeCredentials.add(pc);
        return pc;
    }

    final ProtocolMetaData metaData;
    final DeterministicSeed seed;
    final SecureRandom sr;
    final KeyPairGenerator kpg;
    final public Collection<T> activeCredentials = new ArrayList<>();

    public AbstractPublicKeyProtocolConfiguration(Identity identity, String pmd, ProtocolMetaData metaData) {
        this.identity = identity;
        this.metaData = metaData;

        if (this.identity.protocolCredentials.containsKey(pmd))
            throw new RuntimeException("You cant do this!");

        this.seed = WalletHelper.createSubSeed(identity.seed, pmd);

        log.finest(String.format("Created subseed %s for protocol %s",
                NostrUtil.bytesToHex(Objects.requireNonNull(this.seed.getSeedBytes())), pmd));

        this.sr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);
        this.kpg = createKeyPairGenerator();
        this.identity.protocolCredentials.put(pmd, this);
    }

    private AbstractPublicKeyProtocolConfiguration(Identity identity, String pcd, PublicKeyPersistentData keyPersistentData) {
        this(identity, pcd, keyPersistentData.metaData);
        restoreKey(keyPersistentData.fingerprint);
    }

    AbstractPublicKeyProtocolConfiguration(Identity identity, String pcd, File file) {
        this(identity, pcd, parsePersistentData(file, PublicKeyPersistentData.class));
    }

    static Map<PublicKeyAlg, String> toJavaNameMap = new HashMap<>();

    static {
        toJavaNameMap.put(PublicKeyAlg.rsa, "RSA");
        toJavaNameMap.put(PublicKeyAlg.dsa, "DSA");
        toJavaNameMap.put(PublicKeyAlg.ed25519, "Ed25519");
    }

    static String getJavaAlgName(PublicKeyAlg alg) {
        return toJavaNameMap.get(alg);
    }

    protected KeyPairGenerator createKeyPairGenerator() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(getJavaAlgName(metaData.keyMetaData.pubAlg));
            kpg.initialize(metaData.keyMetaData.pubBits, sr);
            return kpg;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

