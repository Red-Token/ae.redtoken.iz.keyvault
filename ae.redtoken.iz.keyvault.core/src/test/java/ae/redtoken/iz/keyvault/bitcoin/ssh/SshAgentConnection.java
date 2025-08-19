package ae.redtoken.iz.keyvault.bitcoin.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.PublicKey;
import java.util.Base64;

public class SshAgentConnection {
    public ISignAPI api = new TestSSH.TestSignAPI();

    TestSSH.SshTokeReader requestReader;
    TestSSH.SshTokenWriter responseWriter;

    public SshAgentConnection(UnixSocketChannel inChannel) {
        requestReader = new TestSSH.SshTokeReader(inChannel);
        responseWriter = new TestSSH.SshTokenWriter(inChannel);
    }

    @SneakyThrows
    public void processNextToken() {
        TestSSH.SshTokeReader.AbstractSshToken requestToken = requestReader.readSshToken();

        if (requestToken instanceof TestSSH.SshTokeReader.SshAgentCSignRequest) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            TestSSH.SshTokeReader.SshAgentCSignRequest sacsr = (TestSSH.SshTokeReader.SshAgentCSignRequest) requestToken;

            EdDSAPublicKey pk = (EdDSAPublicKey) sacsr.key;
            Ed25519PublicKeyParameters bcParams = new Ed25519PublicKeyParameters(pk.getAbyte(), 0);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcParams);

            // This is the key we need to use the one above does not work atleast not with the Key that we load from file
            PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);

            System.out.println("Public key: " + publicKey);
            System.out.println(publicKey.getClass());

            AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(publicKey.getEncoded());
            byte[] publicKeyBytes = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);

            System.out.println(Base64.getEncoder().encodeToString(publicKeyBytes));

            // Data to be signed.
            byte[] data = sacsr.data;

            byte[] signature = api.sign(publicKeyBytes, data);

            SshKeyType keyType = SshKeyType.fromBcName(publicKey.getAlgorithm());

            TestSSH.SshTokeReader.AbstractSshToken responseToken;
            responseToken = new TestSSH.SshTokeReader.SshAgentSignResponse(new TestSSH.SshTokeReader.SshAgentSignResponse.SshSignature(keyType.sshName, signature));

            System.out.printf("SshToken: %s\n", responseToken);
            responseWriter.writeSshToken(responseToken);

        } else if (requestToken instanceof TestSSH.SshTokeReader.SshAgentCExetion) {
            TestSSH.SshTokeReader.SshAgentFailure failure = new TestSSH.SshTokeReader.SshAgentFailure();
            responseWriter.writeSshToken(failure);


        } else if (requestToken instanceof TestSSH.SshTokeReader.SshAgentCRequestIdentities) {

            PublicKey publicKey = api.getPublicKey();
            byte[] spki = publicKey.getEncoded();

            SubjectPublicKeyInfo info =
                    SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki));

            byte[] raw = info.getPublicKeyData().getBytes();

            if (raw.length != 32) {
                throw new IllegalArgumentException(
                        "Expected 32 bytes but got " + raw.length);
            }

            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(raw, spec);
            PublicKey key = new EdDSAPublicKey(pubSpec);

            TestSSH.SshTokeReader.SshAgentIdentitiesAnswer answer = new TestSSH.SshTokeReader.SshAgentIdentitiesAnswer();
            answer.keys.add(new TestSSH.SshTokeReader.SshAgentIdentitiesAnswer.Key(key, "/home/rene/id_ed25519"));

            responseWriter.writeSshToken(answer);

        } else {
        }
    }

    // TO be removed!
//        SshTokenWriter requestWriter;
//        SshTokeReader responseReader;
}
