package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyProtocolMetaData;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Logger;

public class NostrProtocolConfiguration extends AbstractPublicKeyProtocolConfiguration<NostrProtocolConfiguration.NostrProtocolCredentials> {
    private static final Logger log = Logger.getLogger(NostrProtocolConfiguration.class.getName());

    public static final String pcd = "nostr";

    static {
        Identity.protocolMap.put(pcd, NostrProtocolConfiguration.class);
    }

    public NostrProtocolConfiguration(Identity identity, ProtocolMetaData metaData) {
        super(identity, pcd, metaData);
    }

    public NostrProtocolConfiguration(Identity identity, File file) {
        super(identity, pcd, file);
    }

    private byte[] getRawPublicKey(ECPrivateKey privateKey) {
        try {
            return Schnorr.genPubKey(getRawPrivateKey(privateKey));

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

    public void register(NostrProtocolCredentials npc) {
    }

    public class NostrProtocolCredentials extends AbstractImplementedPublicKeyCredentials {
//            String DEFAULT_KEY_DATA = "zool.json";

        public NostrProtocolCredentials(KeyPair kp) {
            super(kp);
        }

        @Override
        protected String getPCD() {
            return NostrProtocolConfiguration.pcd;
        }

        @Override
        protected ProtocolMetaData getMetaData() {
            return null;
        }

        @Override
        protected byte[] calculateFingerPrint() {
            return NostrProtocolConfiguration.this.calculateFingerPrint(kp);
        }

//            public void persist(Path path) {
//                try {
//                    File file = path.resolve(NostrProtocolConfiguration.pcd).resolve(DEFAULT_KEY_DATA).toFile();
//                    assertDirectoryExists(file.getParentFile());
//                    ObjectMapper om = new ObjectMapper();
//                    om.writeValue(file, new PublicKeyPersistentData(NostrProtocolConfiguration.this.metaData, calculateFingerPrint(kp)));
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//            }
    }
}
