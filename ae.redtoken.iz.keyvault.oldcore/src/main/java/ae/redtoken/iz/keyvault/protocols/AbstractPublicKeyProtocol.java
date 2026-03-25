package ae.redtoken.iz.keyvault.protocols;

import ae.redtoken.iz.keyvault.AbstractPublicKeyCredentials;
import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import nostr.util.NostrUtil;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

/**
 * PublicKeyProtocolConfiguration contains a specific configuration for a given protocol, this includes data like key_alg and key_size.
 *
 * @param <T>
 */
public abstract class AbstractPublicKeyProtocol<M extends AbstractMetaData, T extends AbstractPublicKeyCredentials<M>> extends AbstractProtocol {
    static Logger log = LoggerFactory.getLogger(AbstractPublicKeyProtocol.class);

    abstract protected Class<T> getCredentialClass();

    void recallCredentials(Path protocolDir) {
        Arrays.stream(Objects.requireNonNull(protocolDir.toFile().listFiles()))
                .filter(file -> file.getName().endsWith(".json"))
                .forEach(this::recallCredential);
    }

    public void persistCredentials(Path idPath, T credentials) {
        Path path = idPath.resolve(getProtocolName()).resolve("defaultCredentials.json");
        credentials.persist(path.toFile());
    }

    @SneakyThrows
    private void recallCredential(File file) {
        Constructor<T> constructor = getCredentialClass().getDeclaredConstructor(SecureRandom.class, File.class);
        T credential = constructor.newInstance(this.sr, file);
        activeCredentials.add(credential);
    }

    // TODO! WE NET TO THINK A LOT HERE! How shall we handle randomness

    @SneakyThrows
    public final T createCredential(M metaData) {
        Constructor<T> constructor = getCredentialClass().getDeclaredConstructor(SecureRandom.class, metaData.getClass());
        T credential = constructor.newInstance(this.sr, metaData);
        activeCredentials.add(credential);
        return credential;
    }

    //    final ProtocolMetaData metaData;
    final public Collection<T> activeCredentials = new ArrayList<>();

    protected AbstractPublicKeyProtocol(Identity identity) {
        super(identity);
        this.identity.protocolCredentials.put(getProtocolName(), this);
    }

    /**
     * @param identity
     * @param protocolRoot idRoot
     */
    protected AbstractPublicKeyProtocol(Identity identity, Path protocolRoot) {
        this(identity);
//        recallCredentials(idRoot.resolve(getProtocolName()));
        recallCredentials(protocolRoot);
    }
}

