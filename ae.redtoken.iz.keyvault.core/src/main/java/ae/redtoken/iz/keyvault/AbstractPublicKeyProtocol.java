package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocolls.AbstractCredentialsMetaData;
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
public abstract class AbstractPublicKeyProtocol<M extends AbstractCredentialsMetaData, T extends AbstractPublicKeyCredentials<M>> {
    static Logger log = LoggerFactory.getLogger(AbstractPublicKeyProtocol.class);

    private final Identity identity;

    abstract protected Class<T> getCredentialClass();

    abstract protected String getProtocolName();

    void recallCredentials(Path protocolDir) {
        Arrays.stream(Objects.requireNonNull(protocolDir.toFile().listFiles()))
                .filter(file -> file.getName().endsWith(".json"))
                .forEach(this::recallCredential);
    }

    public void persistCredentials(Path idPath, T credentials) {
        credentials.persist(idPath.resolve(getProtocolName()).resolve("defaultCredentials.json").toFile());
    }

    @SneakyThrows
    private void recallCredential(File file) {
        Constructor<T> constructor = getCredentialClass().getDeclaredConstructor(SecureRandom.class, File.class);
        T credential = constructor.newInstance(this.sr, file);
        activeCredentials.add(credential);
    }

    @SneakyThrows
    public final T createCredential(M metaData) {
        Constructor<T> constructor = getCredentialClass().getDeclaredConstructor(SecureRandom.class, metaData.getClass());
        T credential = constructor.newInstance(this.sr, metaData);
        activeCredentials.add(credential);
        return credential;
    }

    //    final ProtocolMetaData metaData;
    final DeterministicSeed seed;
    final SecureRandom sr;
    final public Collection<T> activeCredentials = new ArrayList<>();

    protected AbstractPublicKeyProtocol(Identity identity) {
        this.identity = identity;
        String pmd = getProtocolName();

        if (this.identity.protocolCredentials.containsKey(pmd))
            throw new RuntimeException("You cant do this!");

        this.seed = WalletHelper.createSubSeed(identity.seed, pmd);
        log.trace("Created subseed {} for protocol {}", NostrUtil.bytesToHex(Objects.requireNonNull(this.seed.getSeedBytes())), pmd);

        this.sr = WalletHelper.getDeterministicSecureRandomFromSeed(seed);
        this.identity.protocolCredentials.put(pmd, this);
    }

    /**
     * @param identity
     * @param protocolRoot idRoot
     */
    AbstractPublicKeyProtocol(Identity identity, Path protocolRoot) {
        this(identity);
//        recallCredentials(idRoot.resolve(getProtocolName()));
        recallCredentials(protocolRoot);
    }
}

