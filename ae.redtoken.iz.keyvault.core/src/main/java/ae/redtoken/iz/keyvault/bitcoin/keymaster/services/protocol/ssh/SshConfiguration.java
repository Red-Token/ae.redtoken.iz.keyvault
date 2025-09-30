package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;

import java.util.Objects;

public final class SshConfiguration {
    public SshKeyType type;
    public int size;

    public SshConfiguration(SshKeyType type, int size) {
        this.type = type;
        this.size = size;
    }

    public SshConfiguration() {
    }

    public SshKeyType type() {
        return type;
    }

    public int size() {
        return size;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (SshConfiguration) obj;
        return Objects.equals(this.type, that.type) &&
                this.size == that.size;
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, size);
    }

    @Override
    public String toString() {
        return "SshConfiguration[" +
                "type=" + type + ", " +
                "size=" + size + ']';
    }
}

