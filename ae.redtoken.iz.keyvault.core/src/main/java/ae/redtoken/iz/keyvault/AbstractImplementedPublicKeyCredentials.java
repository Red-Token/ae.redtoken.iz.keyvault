package ae.redtoken.iz.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;

import static ae.redtoken.util.Util.assertDirectoryExists;

public abstract class AbstractImplementedPublicKeyCredentials {
    public final KeyPair kp;

    public AbstractImplementedPublicKeyCredentials(KeyPair kp) {
        this.kp = kp;
    }

    abstract protected String getPCD();

    abstract protected ProtocolMetaData getMetaData();

    abstract protected byte[] calculateFingerPrint();

    protected String getDefaultFileName() {
        return "defaultKeyCredentials.json";
    }

    public void persist(Path path) {
        persist(path.resolve(getPCD()).resolve(getDefaultFileName()).toFile());
    }

    public void persist(File file) {
        try {
            ObjectMapper om = new ObjectMapper();
            assertDirectoryExists(file.getParentFile());
            om.writeValue(file, new PublicKeyPersistentData(getMetaData(), calculateFingerPrint()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
