package ae.redtoken.iz.keyvault.protocols.nostr;

import ae.redtoken.iz.keyvault.protocols.AbstractMetaData;
import ae.redtoken.lib.PublicKeyProtocolMetaData;

public class NostrMetaData extends AbstractMetaData {
    public NostrMetaData(PublicKeyProtocolMetaData publicKeyMetadata) {
        super(publicKeyMetadata);
    }

    public NostrMetaData() {
        super();
    }
}
