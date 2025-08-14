package ae.redtoken.iz.keyvault.bitcoin.ssh;

import org.junit.jupiter.api.Test;

public class TestKeyType {

    @Test
    void testEnum() {

        SshKeyType type = SshKeyType.ED25519;

        System.out.println(type);
        System.out.println(type.sshName);
    }
}
