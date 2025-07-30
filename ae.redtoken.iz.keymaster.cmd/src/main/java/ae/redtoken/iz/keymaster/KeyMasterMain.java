package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.UdpRequestProcessor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.SystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.params.RegTestParams;
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
import java.util.concurrent.Callable;

@Slf4j
@CommandLine.Command(name = "iz-keymaster", mixinStandardHelpOptions = true, version = "v 0.0.1",
        description = "Keeper of keys",
        subcommands = {
                KeyMasterMain.KeyMaster.class,
                KeyMasterMain.Avatar.class,
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

    @CommandLine.Command(name = "avatar",
            mixinStandardHelpOptions = true,
            subcommands = {
                    Avatar.Start.class
            })
    static class Avatar {
        @CommandLine.Command(name = "start")
        static class Start extends AbstractSubCommand {

            @SneakyThrows
            @Override
            public void execute() {
                System.out.println("SSSSS");

                String password = "Open Sesame!";
                AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(password);

                // Create the KeyMasterExecutor

                final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.PORT);

                SystemAvatar spawn = spawnPoint.spawn();

                spawnPoint.loginThread.join();


                System.out.println("Spawned!");

                spawn.upLinkService.join();


                System.out.println("Done");
            }
        }
    }

    @CommandLine.Command(name = "keymaster",
            mixinStandardHelpOptions = true,
            subcommands = {
                    KeyMaster.Start.class
            })
    static class KeyMaster {
        @CommandLine.Command(name = "start")
        static class Start extends AbstractSubCommand {
            @CommandLine.Option(names = "--size", description = "Seed size")
            Integer size = 32;

            @CommandLine.Option(names = "--master-seed-file", description = "The name of the master-seed file", defaultValue = "master-seed")
            protected Path masterSeedPath;

            @CommandLine.Option(names = "--passphrase", description = "Passphrase for the master-seed")
            String passphrase = "";

            @SneakyThrows
            @Override
            public void execute() {
                System.out.println("Seed size: " + size);
//                DeterministicSeed ds = WalletHelper.generateDeterministicSeed(size, passphrase);
//                WalletHelper.writeMnemonicWordsToFile(ds, masterSeedPath.toFile());
//                log.info("Created master-seed in {}", masterSeedPath);

                // Lets go jeffry
                RegTestParams params = RegTestParams.get();
                BitcoinNetwork network = BitcoinNetwork.REGTEST;
                ScriptType scriptType = ScriptType.P2PKH;

                String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
                DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");

                List<ScriptType> scriptTypes = List.of(scriptType);
                KeyVault kv = new KeyVault(network, ds);

                KeyMasterStackedService keyMaster = new KeyMasterStackedService(kv);
                IdentityStackedService identity = new IdentityStackedService(keyMaster, "bob@teahouse.wl");
                BitcoinProtocolStackedService bp = new BitcoinProtocolStackedService(identity);
                BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
                BitcoinConfigurationStackedService bc = new BitcoinConfigurationStackedService(bp, bitconf);

                String password = "Open Sesame!";
//                AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(password);

                // Create the KeyMasterExecutor
                KeyMasterExecutor kmr = new KeyMasterExecutor(keyMaster);

                final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.PORT);
                final DatagramSocket socket = new DatagramSocket();
                socket.connect(avatarSocketAddress);

                Thread t2 = new Thread(new UdpRequestProcessor(kmr, socket));
                t2.start();

                Thread t = new Thread(() -> {
                    try {
                        Thread.sleep(1000);

                        //Log in
                        DatagramPacket packet = new DatagramPacket(password.getBytes(), password.length(), avatarSocketAddress);
                        socket.send(packet);

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
                t.start();
                t.join();

                t2.join();

                System.out.println("Done!");
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
