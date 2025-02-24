package ae.redtoken.iz.keyvault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public class SshProtocol extends AbstractPublicKeyProtocol<SshMetaData, SshCredentials> {
    static Logger log = LoggerFactory.getLogger(SshProtocol.class);

    static final String pcd = "ssh";

    static {
        Identity.protocolMap.put(pcd, SshProtocol.class);
    }

    // This will be called when we create
    public SshProtocol(Identity identity) {
        super(identity);
    }

    // This will be called when we restore
    public SshProtocol(Identity identity, Path idPath) {
        super(identity, idPath);
    }


    @Override
    protected Class<SshCredentials> getCredentialClass() {
        return SshCredentials.class;
    }

    @Override
    protected String getProtocolName() {
        return pcd;
    }

}
