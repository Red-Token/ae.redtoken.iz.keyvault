package ae.redtoken.iz.keyvault.bitcoin.keyvault;

enum KeyType {
    RSA("RSA", "rsa"),
    Ed25519("Ed25519", "ed25519");

    final String javaAlgName;
    final String sshAlgName;

    KeyType(String javaAlgName, String sshAlgName) {
        this.javaAlgName = javaAlgName;
        this.sshAlgName = sshAlgName;
    }
}
