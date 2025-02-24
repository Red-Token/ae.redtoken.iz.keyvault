package ae.redtoken.iz.keyvault.protocols.nostr;

import ae.redtoken.iz.keyvault.AbstractPublicKeyCredentials;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;

public class NostrCredentials extends AbstractPublicKeyCredentials<NostrMetaData> {

    public NostrCredentials(SecureRandom sr, NostrMetaData metaData) {
        super(sr, metaData);
    }

    public NostrCredentials(SecureRandom sr, File file) {
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

    static private byte[] getRawPrivateKey(ECPrivateKey privateKey) {
        return NostrUtil.bytesFromBigInteger(privateKey.getS());
    }


    static private byte[] getRawPublicKey(ECPrivateKey privateKey) {
        try {
            return Schnorr.genPubKey(getRawPrivateKey(privateKey));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
