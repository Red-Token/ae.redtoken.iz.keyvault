package ae.redtoken.iz.keyvault;

import ae.redtoken.cf.sm.nostr.NostrExporter;
import ae.redtoken.cf.sm.openpgp.OpenPGPExporter;
import ae.redtoken.cf.sm.ssh.OpenSshExporter;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrCredentials;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrMetaData;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrProtocol;
import ae.redtoken.iz.keyvault.protocols.openpgp.OpenPGPCredentials;
import ae.redtoken.iz.keyvault.protocols.openpgp.OpenPGPMetaData;
import ae.redtoken.iz.keyvault.protocols.openpgp.OpenPGPProtocol;
import ae.redtoken.iz.keyvault.protocols.ssh.SshCredentials;
import ae.redtoken.iz.keyvault.protocols.ssh.SshMetaData;
import ae.redtoken.iz.keyvault.protocols.ssh.SshProtocol;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import ae.redtoken.util.WalletHelper;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

@Slf4j
@Command(name = "iz-keyvault", mixinStandardHelpOptions = true, version = "v 0.0.1",
        description = "Generates or restores keys for different protocols",
        subcommands = {
                KeyVaultMain.MasterSeed.class,
//                KeyVaultMain.CryptoModule.class,
                KeyVaultMain.IdentityModule.class,
                KeyVaultMain.SshProtocolModule.class,
                KeyVaultMain.NostrProtocolModule.class,
                KeyVaultMain.OpenPGPProtocolModule.class,
//                KeyVaultMain.X509ProtocolModule.class
        })
class KeyVaultMain implements Callable<Integer> {

    @Command(name = "master-seed",
            mixinStandardHelpOptions = true,
            subcommands = {
                    MasterSeed.Create.class
            })
    static class MasterSeed {

        @Command(name = "create")
        static class Create extends IZKeyVaultSubCommand {
            @Option(names = "--size", description = "Seed size")
            Integer size = 32;

            @Option(names = "--sub-seed-from", description = "Create a sub-seed based on a this master-seed [path from homedir]")
            Path fromSeedFile = null;

            @Option(names = "--count", description = "Select seed with this count when generating")
            Integer count = 0;

            @Override
            public void execute() {
                if (!vaultRoot.toFile().exists()) {
                    if (!vaultRoot.toFile().mkdirs()) {
                        throw new RuntimeException("Could not create dir for master-seed");
                    }
                }

                if (fromSeedFile != null && !(fromSeedFile.isAbsolute())) {
                    fromSeedFile = Path.of(System.getProperty("user.home")).resolve(seedPath);
                }

                DeterministicSeed ds = fromSeedFile != null
                        ? WalletHelper.createSubSeed(WalletHelper.readMnemonicWordsFromFile(fromSeedFile.toFile()), "sub-seed-" + count)
                        : WalletHelper.generateDeterministicSeed(size);

                WalletHelper.writeMnemonicWordsToFile(ds, seedPath.toFile());
                log.info("Created sub-seed in {}", seedPath);
            }
        }
    }

    @Command(name = "identity", mixinStandardHelpOptions = true, subcommands = {
            IdentityModule.Create.class,
    })
    static class IdentityModule {
        abstract static class IdentityModificationSubCommand extends IdentitySubCommand {
            @Option(names = "--name", description = "The Name", required = true)
            String name;

            @Option(names = "--password", description = "Password to protect the key")
            String password = "";
        }

        @Command(name = "create")
        static class Create extends IdentityModificationSubCommand {

            @SneakyThrows
            @Override
            public void execute() {
                if (idPath.toFile().exists() && !force) {
                    log.error("Id already exists");
                    throw new RuntimeException("id exists");
                }

                if (!idPath.toFile().exists())
                    if (!idPath.toFile().mkdirs()) {
                        log.error("Could not create dir for identity");
                        throw new RuntimeException("Failed to create dir" + idPath);
                    }

                new ObjectMapper().writeValue(metaPath.toFile(), new IdentityMetaData(name));
                log.info("Identity created {}", metaPath);

                this.identity = new Identity(vault, id, name);
            }
        }
    }

    @Command(name = "ssh-keypair", mixinStandardHelpOptions = true, subcommands = {
            SshProtocolModule.Create.class,
            SshProtocolModule.Export.class
    })
    static class SshProtocolModule {
        @Command(name = "create")
        static class Create extends IdentitySubCommand {
            @Option(names = "--alg", description = "PublicKey Algorithm", defaultValue = "ed25519")
//            @Option(names = "--alg", description = "PublicKey Algorithm", defaultValue = "rsa")
            String alg;

            @Option(names = "--alg-size", description = "PublicKey Algorithm Size", defaultValue = "255")
            Integer algSize;

//            @Option(names = "--password", description = "Password to protect the key")
//            String password = "";

            @Option(names = "--persist", description = "Persist the keys on disk")
            boolean persist = true;

            @Override
            public void execute() {
                SshProtocol protocol = new SshProtocol(identity);
                SshMetaData metaData = new SshMetaData(new PublicKeyProtocolMetaData(alg, algSize));
                SshCredentials credentials = protocol.createCredential(metaData);

                if (persist) {
                    protocol.persistCredentials(idPath, credentials);
                }
            }
        }

        @Command(name = "export")
        static class Export extends AbstractIdentityExportSubCommand {

            @Override
            public void init() throws Exception {
                if (toDir == null) {
                    toDir = Path.of(".ssh");
                }

                super.init();
            }

            @Override
            public void execute() {
                SshProtocol spc = (SshProtocol) this.identity.protocolCredentials.get(SshProtocol.PCD);

                spc.activeCredentials.forEach(sshProtocolCredentials -> {
                    OpenSshExporter exporter = new OpenSshExporter(sshProtocolCredentials.kp, toDir, identity.id, force);

                    exporter.exportPublicKey();
                    exporter.exportPrivateKey();
                });
            }
        }
    }

    @Command(name = "nostr-keypair", mixinStandardHelpOptions = true, subcommands = {
            NostrProtocolModule.Create.class,
            NostrProtocolModule.Export.class
    })
    static class NostrProtocolModule {
        @Command(name = "create")
        static class Create extends IdentitySubCommand {
            @Option(names = "--password", description = "Password to protect the key")
            String password = "";

            @Option(names = "--persist", description = "Persist the keys on disk")
            boolean persist = true;

            @Override
            public void execute() {
                NostrProtocol protocol = new NostrProtocol(identity);
                NostrMetaData metaData = new NostrMetaData(null);
                NostrCredentials credentials = protocol.createCredential(metaData);

                if (persist) {
                    protocol.persistCredentials(idPath, credentials);
                }
            }
        }

        @Command(name = "export")
        static class Export extends AbstractIdentityExportSubCommand {

            @Override
            public void init() throws Exception {
                if (toDir == null) {
                    toDir = Path.of("/tmp");
                }

                super.init();
            }

            @Override
            public void execute() {
                NostrProtocol npc = (NostrProtocol) this.identity.protocolCredentials.get(NostrProtocol.PCD);
                npc.activeCredentials.forEach(nostrCredentials -> {
                    NostrExporter exporter = new NostrExporter(nostrCredentials.kp, toDir, identity.id, force);
                    exporter.exportPublicKey();
                    exporter.exportPrivateKey();
                });
            }
        }
    }


    @Command(name = "openpgp-keypair", mixinStandardHelpOptions = true, subcommands = {
            OpenPGPProtocolModule.Create.class,
            OpenPGPProtocolModule.Export.class
//            OpenPGPProtocolModule.UpLoad.class
    })
    static class OpenPGPProtocolModule {
        @Command(name = "create")
        static class Create extends IdentitySubCommand {
            @Option(names = "--alg", description = "PublicKey Algorithm", defaultValue = "rsa")
            String alg;

            @Option(names = "--alg-size", description = "PublicKey Algorithm Size", defaultValue = "2048")
            Integer algSize;

            @Option(names = "--password", description = "Password to protect the key", defaultValue = "")
            String password;

            @Option(names = "--persist", description = "Persist the keys on disk")
            boolean persist = true;

            @Option(names = "--creation-time", description = "The time the key was created")
            long creationTime = new Date().getTime();

            @Override
            public void execute() {
                OpenPGPProtocol protocol = new OpenPGPProtocol(identity);
                OpenPGPMetaData metaData = new OpenPGPMetaData(new PublicKeyProtocolMetaData(alg, algSize), creationTime);
                OpenPGPCredentials credentials = protocol.createCredential(metaData);

                if (persist) {
                    protocol.persistCredentials(idPath, credentials);
                }
            }
        }

        @Command(name = "export")
        static class Export extends AbstractIdentityExportSubCommand {
//            @Option(names = "--to-dir", description = "Target directory", defaultValue = "/tmp/")
//            String toDir;

            @Option(names = "--password", description = "Password to protect the key", defaultValue = "password")
            String password;

            @Override
            public void init() throws Exception {
                if (toDir == null) {
                    toDir = Path.of("/tmp");
                }

                super.init();
            }

            @SneakyThrows
            @Override
            public void execute() {
                init();

                OpenPGPProtocol configuration = (OpenPGPProtocol) this.identity.protocolCredentials.get(OpenPGPProtocol.PCD);
                configuration.activeCredentials.forEach(credentials -> {
                    OpenPGPExporter exporter = new OpenPGPExporter(credentials.kp, toDir,
                            identity.name, identity.id, password, credentials.metaData.creationTime, force);
                    exporter.exportPublicKey();
                    exporter.exportPrivateKey();
                });

            }
        }


//        @Command(name = "upload")
//        static class UpLoad extends IdentitySubCommand {
//            private static final Logger log = LoggerFactory.getLogger(UpLoad.class);
//            KeyVault.Identity.OpenPGPProtocolConfiguration.OpenPGPProtocolCredentials credentials;
//
//            @Option(names = "--hkp-url", description = "URL to HockeyPuckServer", defaultValue = "http://keyserver.lxc:11371")
//            String hkpUrl;
//
//            @Override
//            public void init() throws Exception {
//                super.init();
//                credentials = (KeyVault.Identity.OpenPGPProtocolConfiguration.OpenPGPProtocolCredentials) identity.protocolCredentials.get(KeyVault.Identity.OpenPGPProtocolConfiguration.pmd).activeCredentials.iterator().next();
//            }
//
//            @Override
//            public void execute() {
//                String keyString = credentials.savePublicKeyToString();
//                HockeyPuckClient hpc = new HockeyPuckClient(hkpUrl);
//                IHockeyPuck.RegisterResponse result = hpc.register(keyString);
//                log.debug("Hello", result);
//            }
//        }
    }

//    @Command(name = "x509-keypair", mixinStandardHelpOptions = true, subcommands = {
//            X509ProtocolModule.Create.class,
//            X509ProtocolModule.Register.class
//    })
//    static class X509ProtocolModule {
//
//        @Command(name = "create")
//        static class Create extends IdentitySubCommand {
//            @Option(names = "--alg", description = "PublicKey Algorithm", defaultValue = "rsa")
//            String alg;
//
//            @Option(names = "--alg-size", description = "PublicKey Algorithm Size", defaultValue = "2048")
//            Integer algSize;
//
//            @Option(names = "--hash", description = "Hash Algorithm", defaultValue = "sha")
//            String hash;
//
//            @Option(names = "--hash-size", description = "Hash Algorithm Size", defaultValue = "160")
//            Integer hashSize;
//
//            @Option(names = "--password", description = "Password to protect the key", defaultValue = "")
//            String password;
//
//            @Override
//            public void execute() {
//                KeyVault.Identity.X509ProtocolConfiguration x509ProtocolConfiguration = identity.registerX509Key(alg, algSize, hash, hashSize);
//                KeyVault.Identity.X509ProtocolConfiguration.X509ProtocolCredentials credentials = x509ProtocolConfiguration.createAndRegisterNewCredentials();
//                credentials.saveKeysToDir(idPath.toFile(), password);
//            }
//        }
//
//        @Command(name = "ca-register")
//        static class Register extends IdentitySubCommand {
//            @Option(names = "--self-sign", description = "Self-sign the key", defaultValue = "")
//            boolean selfSign;
//
//            @Override
//            public void execute() {
//
//                if (selfSign) {
//                    System.out.println("Zool is cool!");
//
//                    KeyVault.Identity.X509ProtocolConfiguration.X509ProtocolCredentials credentials =
//                            (KeyVault.Identity.X509ProtocolConfiguration.X509ProtocolCredentials)
//                                    identity.protocolCredentials.get(KeyVault.Identity.X509ProtocolConfiguration.pmd)
//                                            .activeCredentials.iterator().next();
//
//                    PKCS10CertificationRequest req = credentials.getRequest();
//
//                    //TODO Clean up this, make smart profiles
//                    AbstractSecurityProfile sp = new AbstractDefaultFileBasedCa.DefaultTLSClientSecurityProfile();
//
//                    // YES! YES! YES! We use the current time as the serial, the number of selfsigned certs generated
//                    // Should be small
//                    long now = System.currentTimeMillis();
//                    credentials.certificate = CaUtils.selfSignReq(req, sp, credentials.kp, now, BigInteger.valueOf(now));
//                    credentials.saveCertificate(idPath.toFile());
//                } else {
//                    throw new UnsupportedOperationException();
//                }
//            }
//        }
//    }

    abstract static class IZKeyVaultSubCommand implements Callable<Integer> {
        protected KeyVault vault;
        protected Path seedPath;

        @Option(names = "--seed-file", description = "The name of the seed-file", defaultValue = "seed")
        private Path seedFile;

        @Option(names = "--vault-root", description = "The rood dir of the keyvault", defaultValue = ".config/iz-keyvault")
        Path vaultRoot;

        @Option(names = "--verbose", description = "set the verbosity level")
        String verbosity;

        @Option(names = "--force", description = "Overwrite data")
        boolean force = false;

        public void init() throws Exception {

            if (verbosity != null) {
                setLogLevel(verbosity);
            }

            // Make wallet-root absolute if its does not start with .
            if (!(vaultRoot.isAbsolute() || vaultRoot.startsWith("."))) {
                vaultRoot = Path.of(System.getProperty("user.home")).resolve(vaultRoot);
            }

            seedPath = seedFile.isAbsolute() ? seedFile : vaultRoot.resolve(seedFile);

            if (seedPath.toFile().exists())
                vault = KeyVault.fromSeedFile(seedPath.toFile());
        }

        abstract public void execute();

        @Override
        final public Integer call() throws Exception {
            init();
            execute();
            return 0;
        }
    }

    abstract static class IdentitySubCommand extends IZKeyVaultSubCommand {
        public static class IdentityMetaData {
            static final String path = ".metadata.json";
            public String name;

            public IdentityMetaData(String name) {
                this.name = name;
            }

            public IdentityMetaData() {
            }
        }

        protected Path idPath;
        protected Path metaPath;
        protected Identity identity;

        //        @Option(names = "--id", description = "The identity", required = true)
        @Option(names = "--id", description = "The identity", required = true, defaultValue = "default")
        String id;

        @Option(names = "--set-as-default", description = "Set as the default identity", defaultValue = "true")
        boolean updateDefault;

        @Override
        public void init() throws Exception {
            super.init();

            if (id.equals("default")) {
                Path defaultIdPath = vaultRoot.resolve("default");

                if (!defaultIdPath.toFile().exists()) {
                    throw new RuntimeException("Default identity does not exist");
                }

                Path target = Files.readSymbolicLink(defaultIdPath);
                id = target.toFile().getName();
            }

            idPath = vaultRoot.resolve(id);
            metaPath = idPath.resolve(IdentityMetaData.path);

            if (idPath.toFile().exists()) {
                ObjectMapper om = new ObjectMapper();
                IdentityMetaData metaData = om.readValue(metaPath.toFile(), IdentityMetaData.class);
                this.identity = new Identity(vault, id, metaData.name);

                // Load the keys from disk
                this.identity.recallAllProtocols(idPath);
            }

            if (updateDefault) {
                Path defaultIdPath = vaultRoot.resolve("default");
                Files.deleteIfExists(defaultIdPath);
                Files.createSymbolicLink(defaultIdPath, idPath);
                log.info("Default identity updated to {}", id);
            }
        }
    }

    abstract static class AbstractIdentityExportSubCommand extends IdentitySubCommand {
        @Option(names = "--to-dir", description = "Target directory")
        protected Path toDir;

        @Override
        public void init() throws Exception {
            super.init();

            // Relate toDir to home
            toDir = toDir == null || toDir.isAbsolute() || toDir.startsWith("./")
                    ? toDir
                    : Path.of(System.getProperty("user.home")).resolve(toDir);

            log.debug("toDir: {}", toDir);
        }
    }


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

    @Override
    public Integer call() throws Exception {
        return 0;
    }

    // master-seed create
    // identity create rene.malmgren@h3.se
    // ssh-keypair create --id="rene.malmgren@h3.se" --alg=rsa --alg-size=3072
    // pgp-keypair create --id="rene.malmgren@h3.se" --alg=rsa --alg-size=2048 --name="Rene Malmgren"
    // x509-keypair create --id="rene.malmgren@h3.se" --alg=rsa --alg-size=2048 --name="Rene Malmgren"
    // identity restore --id=rene.malmgren@h3.se --restore-all-modules

    public static int call(String[] args) {
        return new CommandLine(new KeyVaultMain()).setTrimQuotes(true).execute(args);
    }

    public static void main(String[] args) {
        System.exit(call(args));
    }
}
