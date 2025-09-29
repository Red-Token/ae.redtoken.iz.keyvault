package ae.redtoken.iz.protocolls.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import lombok.SneakyThrows;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

class TestSignAPI implements ISignAPI {

    @SneakyThrows
    @Override
    public PublicKey getPublicKey() {
        AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(Base64.getDecoder().decode("AAAAC3NzaC1lZDI1NTE5AAAAIGsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJ"));
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricKeyParameter);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PublicKey key = converter.getPublicKey(subjectPublicKeyInfo);
        return key;
    }

    @SneakyThrows
    @Override
    public byte[] sign(byte[] publicKey, byte[] data) {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        // Private key
        String privateKeyData = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAIjYDL2g2Ay9oAAAAAtzc2gtZWQyNTUxOQAAACBrC36heTk+GWdArR46Qwz5dhqZf1aBM5nD0MQeNqucyQAAAEDgan2OL0Ka1mdZRYilPPUV6yODmSLuRw9fCBQEwbGUGmsLfqF5OT4ZZ0CtHjpDDPl2Gpl/VoEzmcPQxB42q5zJAAAAAAECAwQF";
        AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(Base64.getDecoder().decode(privateKeyData));

        // This is BC doing the magic
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

//            publicKey.getEncoded();

        SshKeyType keyType = SshKeyType.fromBcName(privateKey.getAlgorithm());

        Signature signature = SecurityUtils.getSignature(keyType.bcName);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
