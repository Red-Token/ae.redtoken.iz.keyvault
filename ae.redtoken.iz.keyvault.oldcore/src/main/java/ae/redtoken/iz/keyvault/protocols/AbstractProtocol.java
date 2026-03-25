package ae.redtoken.iz.keyvault.protocols;

import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.util.WalletHelper;
import nostr.util.NostrUtil;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

abstract public class AbstractProtocol<P extends AbstractProtocol<P, M>, M extends AbstractProtocolMetaData> {
    static Logger log = LoggerFactory.getLogger(AbstractProtocol.class);

    protected final Identity identity;
    protected final DeterministicSeed seed;
    protected final SecureRandom sr;
    Map<String, AbstractConfiguration<P, M>> configurations = new HashMap<>();

    abstract protected String getProtocolName();

    protected AbstractProtocol(Identity identity) {
        this.identity = identity;

        String pmd = getProtocolName();

        if (this.identity.protocolCredentials.containsKey(pmd))
            throw new RuntimeException("You cant do this!");

        this.seed = WalletHelper.createSubSeed(identity.seed, pmd, "");
        log.trace("Created subseed {} for protocol {}", NostrUtil.bytesToHex(Objects.requireNonNull(this.seed.getSeedBytes())), pmd);

        this.sr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);
    }
}
