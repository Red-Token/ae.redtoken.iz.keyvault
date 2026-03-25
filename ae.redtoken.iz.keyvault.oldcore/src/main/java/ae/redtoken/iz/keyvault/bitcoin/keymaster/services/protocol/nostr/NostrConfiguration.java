package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

public final class NostrConfiguration {
    public NostrConfiguration() {
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj != null && obj.getClass() == this.getClass();
    }

    @Override
    public int hashCode() {
        return 1;
    }

    @Override
    public String toString() {
        return "NostrConfiguration[]";
    }
}
