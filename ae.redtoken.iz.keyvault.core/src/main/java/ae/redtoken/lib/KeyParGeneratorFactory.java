package ae.redtoken.lib;

import java.security.KeyPairGenerator;
import java.util.HashMap;

public class KeyParGeneratorFactory {
    static class JavaSecurityParametersMap extends HashMap<PublicKeyAlg, String> {
        static JavaSecurityParametersMap instance = new JavaSecurityParametersMap();

        public JavaSecurityParametersMap() {
            put(PublicKeyAlg.rsa, "RSA");
            put(PublicKeyAlg.dsa, "DSA");
            put(PublicKeyAlg.ed25519, "Ed25519");
        }
    }

    KeyPairGenerator createKeyPairGenerator(PublicKeyAlg alg) {
        try {
            return KeyPairGenerator.getInstance(JavaSecurityParametersMap.instance.get(alg));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
