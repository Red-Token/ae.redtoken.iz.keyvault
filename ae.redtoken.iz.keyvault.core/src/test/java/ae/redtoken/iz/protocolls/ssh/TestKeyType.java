package ae.redtoken.iz.protocolls.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import org.junit.jupiter.api.Test;

public class TestKeyType {

    @Test
    void testEnum() {

        SshKeyType type = SshKeyType.ED25519;

        System.out.println(type);
        System.out.println(type.sshName);
    }
}
