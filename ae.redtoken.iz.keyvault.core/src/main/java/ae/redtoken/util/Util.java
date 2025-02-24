package ae.redtoken.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Util {
    private static final Logger log
            = LoggerFactory.getLogger(Util.class);

    public static void assertDirectoryExists(File dir) {
        if (dir == null) throw new NullPointerException("Directory cannot be null");

        if (dir.exists() && !dir.isDirectory()) {
            throw new IllegalArgumentException("Directory exists and is not a directory: " + dir.getAbsolutePath());
        }

        if (dir.mkdirs()) {
            log.debug("Directory created: {}", dir.getAbsolutePath());
        }
    }

    public static <T> T parsePersistentData(File file, Class<T> cls) {
        try {
            ObjectMapper om = new ObjectMapper();
            return om.readValue(file, cls);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static AsymmetricCipherKeyPair convertJceToBcKeyPair(KeyPair keyPair) {
        try {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyPair.getPublic().getEncoded());
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair convertBcToJceKeyPair(AsymmetricCipherKeyPair bcKeyPair) {
        try {
            byte[] pkcs8Encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(bcKeyPair.getPrivate()).getEncoded();
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
            byte[] spkiEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcKeyPair.getPublic()).getEncoded();
            X509EncodedKeySpec spkiKeySpec = new X509EncodedKeySpec(spkiEncoded);
            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            return new KeyPair(keyFac.generatePublic(spkiKeySpec), keyFac.generatePrivate(pkcs8KeySpec));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
