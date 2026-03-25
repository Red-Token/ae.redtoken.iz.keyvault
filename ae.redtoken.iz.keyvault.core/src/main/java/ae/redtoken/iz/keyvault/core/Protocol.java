package ae.redtoken.iz.keyvault.core;

public enum Protocol {
    BITCOIN(0),
    NOSTR(1237),
    OPENPGP(11371),
    SSH(22);

    private final int coinType;

    Protocol(int coinType) {
        this.coinType = coinType;
    }

    public int coinType() {
        return coinType;
    }
}
