package ae.redtoken.iz.keyvault.protocols.nostr;

import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.iz.keyvault.protocols.AbstractPublicKeyProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public class NostrProtocol
        extends AbstractPublicKeyProtocol<NostrMetaData, NostrCredentials> {
    static Logger log = LoggerFactory.getLogger(NostrProtocol.class);

    public static final String PCD = "nostr";

    // This will be called when we create
    public NostrProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public NostrProtocol(Identity identity, Path idPath) {
        super(identity, idPath);
    }

    @Override
    protected Class<NostrCredentials> getCredentialClass() {
        return NostrCredentials.class;
    }

    @Override
    protected String getProtocolName() {
        return PCD;
    }

}
