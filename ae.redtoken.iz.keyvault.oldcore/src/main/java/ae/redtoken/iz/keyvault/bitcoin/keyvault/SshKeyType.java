package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import java.util.Arrays;

public enum SshKeyType {
    ED25519("ssh-ed25519", "Ed25519");

    public final String sshName;
    public final String bcName;

    SshKeyType(String sshName, String bcName) {
        this.sshName = sshName;
        this.bcName = bcName;
    }

    public static SshKeyType fromSshName(String sshName) {
        return Arrays.stream(SshKeyType.values()).filter(t -> t.sshName.equals(sshName)).findFirst().orElseThrow();
    }

    public static SshKeyType fromBcName(String bcName) {
        return Arrays.stream(SshKeyType.values()).filter(t -> t.bcName.equals(bcName)).findFirst().orElseThrow();
    }

}
