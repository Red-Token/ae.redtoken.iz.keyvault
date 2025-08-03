package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.UdpRequestProcessor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.SystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.util.WalletHelper;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

@Slf4j
@CommandLine.Command(name = "iz-keymaster", mixinStandardHelpOptions = true, version = "v 0.0.1",
        description = "Keeper of keys",
        subcommands = {
                KeyMasterMain.KeyMasterCommand.class,
                KeyMasterMain.AvatarCommand.class,
        })

public class KeyMasterMain implements Callable<Integer> {

    static void setLogLevel(String logLevel) {
        Map<String, Level> logLevels = new HashMap<>();

        logLevels.put("trace", Level.TRACE);
        logLevels.put("debug", Level.DEBUG);
        logLevels.put("info", Level.INFO);
        logLevels.put("warn", Level.WARN);
        logLevels.put("error", Level.ERROR);

        if (!logLevels.containsKey(logLevel)) {
            log.error("Unknown log level: {}", logLevel);
            throw new RuntimeException("Unknown log level: " + logLevel);
        }

        // Get the LoggerContext
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

        // Get the root logger
        Logger rootLogger = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);

        // Set the default log level
        rootLogger.setLevel(logLevels.get(logLevel));
        log.info("Setting log level to {}", logLevels.get(logLevel));
    }

    static Path getFinalPath(Path path, Path relativeRoot) {
        return path == null || path.isAbsolute() || path.startsWith("./") ? path : relativeRoot.resolve(path);
    }

    abstract static class AbstractSubCommand implements Callable<Integer> {
        @CommandLine.Option(names = "--verbose", description = "set the verbosity level")
        String verbosity;

        @CommandLine.Option(names = "--force", description = "Overwrite data")
        protected boolean force = false;

        public void init() throws Exception {
            if (verbosity != null) {
                setLogLevel(verbosity);
            }
        }

        abstract public void execute();

        @Override
        final public Integer call() throws Exception {
            init();
            execute();
            return 0;
        }
    }

    abstract static class AbstractKeyVaultSubCommand extends AbstractSubCommand {
        protected ae.redtoken.iz.keyvault.KeyVault vault;

        @CommandLine.Option(names = "--seed-file", description = "The name of the seed-file", defaultValue = "seed")
        protected Path seedPath;

        @CommandLine.Option(names = "--passphrase", description = "Passphrase for the seed")
        String passphrase = "";

        @CommandLine.Option(names = "--vault-root", description = "The rood dir of the keyvault", defaultValue = ".config/iz-keyvault")
        Path vaultRoot;

        public void init() throws Exception {
            // Make wallet-root absolute if its does not start with .
            vaultRoot = getFinalPath(vaultRoot, Path.of(System.getProperty("user.home")));
            seedPath = getFinalPath(seedPath, vaultRoot);

            if (seedPath.toFile().exists())
                vault = ae.redtoken.iz.keyvault.KeyVault.fromSeedFile(seedPath.toFile(), passphrase);
        }
    }


    @CommandLine.Command(name = "avatar",
            mixinStandardHelpOptions = true,
            subcommands = {
                    AvatarCommand.Start.class
            })
    static class AvatarCommand {
        @CommandLine.Command(name = "start")
        static class Start extends AbstractSubCommand {

            @CommandLine.Option(names = "--passphrase", description = "Passphrase for login")
            String passphrase = AvatarSpawnPoint.DEFAULT_PASSWORD;

            @CommandLine.Option(names = "--spawn-port", description = "Port used for spawning the Avatar")
            int spawnPort = AvatarSpawnPoint.SPAWN_PORT;

            @CommandLine.Option(names = "--service-port", description = "Port for users to connect to the avatar")
            int servicePort = AvatarSpawnPoint.SERVICE_PORT;

            @SneakyThrows
            @Override
            public void execute() {
                AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(spawnPort, passphrase, servicePort);
                SystemAvatar spawn = spawnPoint.spawn();
                log.info("Avatar spawned");

                boolean result = spawn.executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
                System.out.println("Done");
            }
        }
    }

    @CommandLine.Command(name = "keymaster",
            mixinStandardHelpOptions = true,
            subcommands = {
                    KeyMasterCommand.Start.class
            })
    static class KeyMasterCommand {
        @CommandLine.Command(name = "start")
        static class Start extends AbstractSubCommand {
            @CommandLine.Option(names = "--config-root", description = "Root of the config directory", defaultValue = ".config/iz-keymaster")
            protected Path configRoot;

            @CommandLine.Option(names = "--key-vault-root", description = "Root of the config directory for key vault", defaultValue = ".config/iz-keyvault")
            protected Path vaultRoot;

            @CommandLine.Option(names = "--seed-file", description = "The name of the master-seed file", defaultValue = "seed")
            protected Path seedPath;

            @CommandLine.Option(names = "--key-vault-passphrase", description = "Passphrase for the master-seed")
            String keyVaultPassphrase = "";

            @CommandLine.Option(names = "--avatar-passphrase", description = "Passphrase for the avatar")
            String avatarPassphrase = AvatarSpawnPoint.DEFAULT_PASSWORD;

            @CommandLine.Option(names = "--avatar-port", description = "Port for the avatar")
            int avatarPort = AvatarSpawnPoint.SPAWN_PORT;

            @CommandLine.Option(names = "--avatar-host", description = "Host for the avatar")
            String avatarHost = AvatarSpawnPoint.HOSTNAME;

            public void init() throws Exception {
                // Make wallet-root absolute if its does not start with .
                configRoot = getFinalPath(configRoot, Path.of(System.getProperty("user.home")));
                vaultRoot = getFinalPath(vaultRoot, Path.of(System.getProperty("user.home")));
                seedPath = getFinalPath(seedPath, vaultRoot);
            }

            @SneakyThrows
            @Override
            public void execute() {
                BitcoinNetwork network = BitcoinNetwork.REGTEST;
                ScriptType scriptType = ScriptType.P2PKH;
                List<ScriptType> scriptTypes = List.of(scriptType);

                DeterministicSeed ds = WalletHelper.readMnemonicWordsFromFile(seedPath.toFile(), keyVaultPassphrase);
                KeyVault kv = new KeyVault(ds);

                KeyMasterStackedService keyMaster = new KeyMasterStackedService(kv);

                for (String id : Objects.requireNonNull(configRoot.toFile().list())) {
                    IdentityStackedService identity = new IdentityStackedService(keyMaster, id);
                    Path idPath = configRoot.resolve(id);

                    // Protocol
                    for (String protocol : Objects.requireNonNull(idPath.toFile().list())) {
                        AbstractProtocolStackedService ps = ProtocolFactory.createProtocolStackedService(protocol, identity);
                        Path protocolPath = idPath.resolve(protocol);

                        for (String config : Objects.requireNonNull(protocolPath.toFile().list())) {
                            // Configuration
                            Path configPath = protocolPath.resolve(config);
                            AbstractConfigurationStackedService css = ps.createConfigurationStackedService(configPath.toFile());
                        }
                    }
                }

                // Create the KeyMasterExecutor
                KeyMasterExecutor kme = new KeyMasterExecutor(keyMaster);

                final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SPAWN_PORT);
                final DatagramSocket socket = new DatagramSocket();
                socket.connect(avatarSocketAddress);

                DatagramPacket packet = new DatagramPacket(avatarPassphrase.getBytes(), avatarPassphrase.length(), avatarSocketAddress);
                socket.send(packet);

                kme.executor.execute(new UdpRequestProcessor(kme, socket));

                boolean result = kme.executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
                System.out.println("Done!");
            }
        }
    }

    @CommandLine.Command(name = "keyvault",
            mixinStandardHelpOptions = true,
            subcommands = {
                    KeyMasterCommand.Start.class
            })
    static class KeyVaultCommand {
        @CommandLine.Command(name = "start")
        static class Config extends AbstractSubCommand {

            @Override
            public void execute() {
            }
        }
    }


    @Override
    public Integer call() throws Exception {
        return 0;
    }

    public static int call(String[] args) {
        return new CommandLine(new KeyMasterMain()).setTrimQuotes(true).execute(args);
    }

    public static void main(String[] args) {
        System.exit(call(args));
    }
}
