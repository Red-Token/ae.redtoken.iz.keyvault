package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocolls.AbstractCredentialsMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;

public class NostrProtocol
        extends AbstractPublicKeyProtocol<NostrProtocol.NostrMetaData, NostrProtocol.NostrCredentials> {
    static Logger log = LoggerFactory.getLogger(NostrProtocol.class);

    public static final String pcd = "nostr";

    static {
        Identity.protocolMap.put(pcd, NostrProtocol.class);
    }

    // This will be called when we create
    public NostrProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public NostrProtocol(Identity identity, Path idPath) {
        super(identity, idPath);
    }

    static private byte[] getRawPublicKey(ECPrivateKey privateKey) {
        try {
            return Schnorr.genPubKey(getRawPrivateKey(privateKey));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static private byte[] getRawPrivateKey(ECPrivateKey privateKey) {
        return NostrUtil.bytesFromBigInteger(privateKey.getS());
    }

    @Override
    protected Class<NostrCredentials> getCredentialClass() {
        return NostrCredentials.class;
    }

    @Override
    protected String getProtocolName() {
        return pcd;
    }

    public static class NostrMetaData extends AbstractCredentialsMetaData {
        public NostrMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
            super(publicKeyMetadata);
        }

        public NostrMetaData() {
            super();
        }
    }

    public static class NostrCredentials extends AbstractPublicKeyCredentials<NostrMetaData> {

        protected NostrCredentials(SecureRandom sr, NostrMetaData metaData) {
            super(sr, metaData);
        }

        protected NostrCredentials(SecureRandom sr, File file) {
            super(sr, file);
        }

        @Override
        protected Class<NostrMetaData> getMetaDataClass() {
            return NostrMetaData.class;
        }

        @Override
        protected byte[] calculateFingerPrint(KeyPair keyPair) {
            return getRawPublicKey((ECPrivateKey) keyPair.getPrivate());
        }

        @Override
        // TODO Make this generic
        protected KeyPairGenerator createKeyPairGenerator(SecureRandom sr) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
                kpg.initialize(new ECGenParameterSpec("secp256k1"), sr);
                return kpg;

            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        }

    }
}
