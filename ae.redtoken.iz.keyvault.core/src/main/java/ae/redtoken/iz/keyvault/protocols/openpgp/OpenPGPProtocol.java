package ae.redtoken.iz.keyvault.protocols.openpgp;

import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.iz.keyvault.protocols.AbstractPublicKeyProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public class OpenPGPProtocol extends AbstractPublicKeyProtocol<OpenPGPMetaData, OpenPGPCredentials> {
    static Logger log = LoggerFactory.getLogger(OpenPGPProtocol.class);

    public static final String PCD = "openpgp";

    static {
        Identity.protocolMap.put(PCD, OpenPGPProtocol.class);
    }

    // This will be called when we create
    public OpenPGPProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public OpenPGPProtocol(Identity identity, Path idPath) {
        super(identity, idPath);
    }


    @Override
    protected Class<OpenPGPCredentials> getCredentialClass() {
        return OpenPGPCredentials.class;
    }

    @Override
    protected String getProtocolName() {
        return PCD;
    }

}
