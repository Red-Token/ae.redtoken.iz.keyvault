package ae.redtoken.iz.keyvault;

import ae.redtoken.iz.keyvault.protocols.AbstractPublicKeyProtocol;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

public class Identity {
    private static final Logger log = Logger.getLogger(Identity.class.getName());

    public static final Map<String, Class<? extends AbstractPublicKeyProtocol<?, ? extends AbstractPublicKeyCredentials<?>>>> protocolMap = new HashMap<>();

    final String name;
    final protected String id;
    public final DeterministicSeed seed;

    public Identity(KeyVault keyVault, String id, String name) {
        this.id = id;
        this.seed = WalletHelper.createSubSeed(keyVault.seed, id);
        this.name = name;
    }

    @SneakyThrows
    private void recallProtocol(File protocolDir) {
        protocolMap.get(protocolDir.getName()).getDeclaredConstructor(Identity.class, Path.class)
                .newInstance(this, protocolDir.toPath());
    }

    void recallAllProtocols(Path idPath) {
        File idDir = idPath.toFile();

        if (!idDir.exists() || !idDir.isDirectory()) {
            log.warning("Path does not exist or is not a directory");
            return;
        }

        Arrays.stream(Objects.requireNonNull(idDir.listFiles()))
                .filter(file -> protocolMap.containsKey(file.getName()))
                .forEach(this::recallProtocol);
    }

    public Map<String, AbstractPublicKeyProtocol<?, ? extends AbstractPublicKeyCredentials<?>>> protocolCredentials = new HashMap<>();
}
