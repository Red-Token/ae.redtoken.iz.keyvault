package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocols.AbstractMetaData;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static ae.redtoken.util.Util.assertDirectoryExists;

public abstract class AbstractPublicKeyCredentials<T extends AbstractMetaData> extends AbstractCredentials {
    static Logger log = LoggerFactory.getLogger(AbstractPublicKeyCredentials.class);
    static long KEY_RESTORE_MAX_TRIES = 1000;

    public final KeyPair kp;
    protected final T metaData;

    // This will create a key
    protected AbstractPublicKeyCredentials(SecureRandom sr, T metaData) {
        this.metaData = metaData;
        this.kp = initKeyPair(createKeyPairGenerator(sr));
    }

    // This will restore a key from a file
    protected AbstractPublicKeyCredentials(SecureRandom sr, File file) {
        this.metaData = loadMetaData(file);
        this.kp = initKeyPair(createKeyPairGenerator(sr));
    }

    private KeyPair initKeyPair(KeyPairGenerator kpg) {
        if (metaData.fingerprint != null)
            return restoreKey(kpg, KEY_RESTORE_MAX_TRIES);

        return createKeyPair(kpg);
    }

    protected KeyPair createKeyPair(KeyPairGenerator kpg) {
        KeyPair kp = kpg.generateKeyPair();
        metaData.fingerprint = calculateFingerPrint(kp);
        return kp;
    }

    protected KeyPairGenerator createKeyPairGenerator(SecureRandom sr) {
        return KeyPairGeneratorFactory.create(metaData.publicKeyMetadata, sr);
    }

    @SneakyThrows
    private T loadMetaData(File file) {
        return new ObjectMapper().readValue(file, getMetaDataClass());
    }

    private KeyPair restoreKey(KeyPairGenerator kpg, long maxTries) {
        log.trace("looking for key: {}", Base64.getEncoder().encodeToString(metaData.fingerprint));

        for (int i = 0; i < maxTries; i++) {
            KeyPair candidate = kpg.genKeyPair();
            byte[] calculateFingerPrint = calculateFingerPrint(candidate);
            log.trace("generated key: {}", Base64.getEncoder().encodeToString(calculateFingerPrint));

            if (Arrays.equals(metaData.fingerprint, calculateFingerPrint)) {
                log.debug("Key restored");
                return candidate;
            }
        }

        throw new RuntimeException("No key found");
    }

//    public final byte[] calculateFingerPrint() {
//        return calculateFingerPrint(kp);
//    }

    abstract protected Class<T> getMetaDataClass();
    abstract protected byte[] calculateFingerPrint(KeyPair keyPair);

//    abstract protected String getPCD();
//    protected String getDefaultFileName() {
//        return "defaultKeyCredentials.json";
//    }
//    public void persist(Path path) {
//        persist(path.resolve(getPCD()).resolve(getDefaultFileName()).toFile());
//    }

    @SneakyThrows
    public void persist(File file) {
        ObjectMapper om = new ObjectMapper();
        assertDirectoryExists(file.getParentFile());
        om.writeValue(file, metaData);
        log.info("persisting credential {}", file.getAbsolutePath());
    }
}
