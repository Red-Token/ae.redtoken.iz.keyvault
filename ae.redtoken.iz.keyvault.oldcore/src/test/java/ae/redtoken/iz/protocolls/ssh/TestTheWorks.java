package ae.redtoken.iz.protocolls.ssh;

import lombok.SneakyThrows;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class TestTheWorks {

    public static final Map<String, String> algMap = new HashMap<>();

    static {
        algMap.put("RSA", "rsa");
        algMap.put("DSA", "dsa");
        algMap.put("Ed25519", "ed25519");
        algMap.put("EdDSA", "ed25519");
    }

    static protected void exportPublicKey(OutputStream stream, String email, PublicKey publicKey) throws IOException {
        AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(publicKey.getEncoded());
        byte[] b = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);
        String keyString = Base64.getEncoder().encodeToString(b);

        String alg =  algMap.get(publicKey.getAlgorithm());

        String s = String.format("ssh-%s %s %s", alg, Base64.getEncoder().encodeToString(b), email);
        System.out.println(s);
        stream.write(s.getBytes(StandardCharsets.UTF_8));
    }

    @SneakyThrows
    @Test
    void name() {

        Process ps = Runtime.getRuntime().exec(new String[]{"ls", "-l"});
        ps.waitFor();

        BufferedReader br = new BufferedReader(new InputStreamReader(ps.getInputStream()));
        br.lines().toList().forEach(System.out::println);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
//        keyPairGenerator.initialize(2048);

        KeyPair kp = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = kp.getPublic();

        AsymmetricKeyParameter pubKeyParams = PublicKeyFactory.createKey(publicKey.getEncoded());
        byte[] b = OpenSSHPublicKeyUtil.encodePublicKey(pubKeyParams);

        String keyString = Base64.getEncoder().encodeToString(b);
        String alg =  algMap.get(publicKey.getAlgorithm());
        String email = "rene.malmgren@h3.se";

        String s = String.format("ssh-%s %s %s", alg, Base64.getEncoder().encodeToString(b), email);
        System.out.println(s);

        FileOutputStream stream = new FileOutputStream(Path.of("/tmp/zool.pub").toFile());
        stream.write(s.getBytes(StandardCharsets.UTF_8));
//        exportPublicKey(new FileOutputStream(, "rene.malmgren@gmail.com", publicKey);
//
//        OpenSshExporter exporter = new OpenSshExporter(kp, Path.of("/tmp/"), "rene.malmgren@h3.se", true);

//        exporter.exportPublicKey();

    }
}
