package ae.redtoken.iz.keyvault.protocols.bitcoin;

import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.iz.keyvault.protocols.AbstractProtocol;
import ae.redtoken.iz.keyvault.protocols.AbstractPublicKeyProtocol;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public class BitcoinProtocol extends AbstractProtocol<BitcoinProtocol, BitcoinMetaData> {
    static Logger log = LoggerFactory.getLogger(BitcoinProtocol.class);

    public static final String PCD = "bitcoin";

    // This will be called when we create
    public BitcoinProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public BitcoinProtocol(Identity identity, Path idPath) {
        super(identity);
    }

    @Override
    protected String getProtocolName() {
        return PCD;
    }

    public DeterministicSeed getSeed() {
        return this.seed;
    }
}
