package ae.redtoken.iz.keyvault.bitcoin.ssh;

import java.util.Arrays;

enum SshKeyType {
    ED25519("ssh-ed25519", "Ed25519");

    final String sshName;
    final String bcName;

    SshKeyType(String sshName, String bcName) {
        this.sshName = sshName;
        this.bcName = bcName;
    }

    static SshKeyType fromSshName(String sshName) {
        return Arrays.stream(SshKeyType.values()).filter(t -> t.sshName.equals(sshName)).findFirst().orElseThrow();
    }

    static SshKeyType fromBcName(String bcName) {
        return Arrays.stream(SshKeyType.values()).filter(t -> t.bcName.equals(bcName)).findFirst().orElseThrow();
    }

}
