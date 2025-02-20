package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyAlg;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.HashMap;
import java.util.Set;

public class TestZool {

    @Test
    void testHashAlg() {

//        Map<PublicKeyAlg, JavaParameters> map = new HashMap<>();
//
//        map.put(PublicKeyAlg.ecdsa, new JavaParameters("Ed25519", "BC"));
//
//        KeyPairGenerator keyPairGenerator = null;
//        try {
//            keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
//
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }

        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println("Provider: " + provider.getName());

            // Get all services provided by this provider
            Set<Provider.Service> services = provider.getServices();

            // Iterate through each service
            for (Provider.Service service : services) {
                // Check if the service is related to keys
                if (isKeyRelatedService(service.getType())) {
                    System.out.println("  Algorithm: " + service.getAlgorithm());
                }
            }
            System.out.println();
        }


        String str = "ecdsa";

        PublicKeyAlg hashAlg = PublicKeyAlg.valueOf(str);

        System.out.println(hashAlg);


    }

    private static boolean isKeyRelatedService(String type) {
        return type.equalsIgnoreCase("KeyGenerator") ||
                type.equalsIgnoreCase("KeyPairGenerator") ||
                type.equalsIgnoreCase("KeyFactory") ||
                type.equalsIgnoreCase("KeyAgreement") ||
                type.equalsIgnoreCase("KeyManagerFactory") ||
                type.equalsIgnoreCase("KeyStore");
    }
}
