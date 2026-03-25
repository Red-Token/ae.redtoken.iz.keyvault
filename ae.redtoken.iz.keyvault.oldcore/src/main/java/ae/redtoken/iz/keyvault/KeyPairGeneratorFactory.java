package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyAlg;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import lombok.SneakyThrows;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

class KeyPairGeneratorFactory {
    static Map<PublicKeyAlg, String> toJavaNameMap = new HashMap<>();

    static {
        toJavaNameMap.put(PublicKeyAlg.rsa, "RSA");
        toJavaNameMap.put(PublicKeyAlg.dsa, "DSA");
        toJavaNameMap.put(PublicKeyAlg.ed25519, "Ed25519");
    }

    static String getJavaAlgName(PublicKeyAlg alg) {
        return toJavaNameMap.get(alg);
    }

    @SneakyThrows
    static KeyPairGenerator create(PublicKeyProtocolMetaData metaData, SecureRandom sr) {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(getJavaAlgName(metaData.pubAlg));
        kpg.initialize(metaData.pubBits, sr);
        return kpg;
    }
}
