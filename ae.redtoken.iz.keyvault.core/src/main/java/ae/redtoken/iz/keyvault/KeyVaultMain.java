package ae.redtoken.iz.keyvault;

import ae.redtoken.cf.sm.nostr.NostrExporterBuilder;
import ae.redtoken.cf.sm.ssh.SshExporterBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bitcoinj.wallet.DeterministicSeed;
import org.blkzn.wallet.WalletHelper;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(name = "wallet", mixinStandardHelpOptions = true, version = "checksum 4.0",
        description = "Generates or restores keys for different protocols",
        subcommands = {
                KeyVaultMain.MasterSeed.class,
//                KeyVaultMain.CryptoModule.class,
                KeyVaultMain.IdentityModule.class,
                KeyVaultMain.SshProtocolModule.class,
                KeyVaultMain.NostrProtocolModule.class,
//                KeyVaultMain.OpenPGPProtocolModule.class,
//                KeyVaultMain.X509ProtocolModule.class
        })
public class KeyVaultMain implements Callable<Integer> {

    @Command(name = "master-seed",
            mixinStandardHelpOptions = true,
            subcommands = {
                    MasterSeed.Create.class
            })
    static class MasterSeed {

        @Command(name = "create")
        static class Create extends WalletSubCommand {
            @Option(names = "--size", description = "Seed size")
            Integer size = 32;

            @Override
            public void execute() {
                if (!walletRoot.toFile().exists()) {
                    if (!walletRoot.toFile().mkdirs()) {
                        throw new RuntimeException("Could not create dir for master-seed");
                    }
                }

                DeterministicSeed ds = WalletHelper.generateDeterministicSeed(size);
                WalletHelper.writeMnemonicWordsToFile(ds, seedPath.toFile());
            }
        }
    }

//    @Command(name = "crypto", mixinStandardHelpOptions = true, subcommands = {
//            CryptoModule.FreshAddress.class,
//            CryptoModule.Balance.class
//    })
//    static class CryptoModule {
//        abstract static class CryptoSubCommand extends WalletSubCommand {
//        }
//
//        @Command(name = "fresh-address")
//        static class FreshAddress extends CryptoSubCommand {
//            @Override
//            public void execute() {
//                String address = wallet.client.wallet.freshReceiveAddress().toString();
//                System.out.println(address);
//            }
//        }
//
//        @Command(name = "balance")
//        static class Balance extends CryptoSubCommand {
//            @Override
//            public void execute() {
//                String balance = wallet.client.wallet.getBalance().toString();
//                System.out.println(balance);
//            }
//        }
//
//    }

    @Command(name = "identity", mixinStandardHelpOptions = true, subcommands = {
            IdentityModule.Create.class,
            IdentityModule.Restore.class,
    })
    static class IdentityModule {
        abstract static class IdentityModificationSubCommand extends IdentitySubCommand {
            @Option(names = "--force", description = "Force creation")
            boolean force = false;

            @Option(names = "--register", description = "Register the identity with BlkZn")
            boolean register = false;

            @Option(names = "--name", description = "The Name", required = true)
            String name;

            @Option(names = "--password", description = "Password to protect the key")
            String password = "";
        }

        @Command(name = "create")
        static class Create extends IdentityModificationSubCommand {

            @Override
            public void execute() {
                if (idPath.toFile().exists() && !force) {
                    throw new RuntimeException("id exists");
                }

                if (!idPath.toFile().exists())
                    if (!idPath.toFile().mkdirs())
                        throw new RuntimeException("Failed to create dir" + idPath);

                try {
                    new ObjectMapper().writeValue(metaPath.toFile(), new IdentityMetaData(name));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                this.identity = wallet.new Identity(id, name);

//                if (register) {
//                    final String BASE_URL = "http://s04.labs.h3.se:8090/";
//                    GrantRestClient grc = new GrantRestClient(BASE_URL + "granter/");
//
//                    IGrantFinder gf = zone -> new IGranter() {
//                        @Override
//                        public GrantResponse grant(GrantRequest gr) {
//                            GrantResponse grs = grc.grant(gr);
//                            try {
//                                Thread.sleep(5000);
//                            } catch (InterruptedException e) {
//                                e.printStackTrace();
//                            }
//                            return grs;
//                        }
//
//                        @Override
//                        public SignatureResponse signGrant(SignatureRequest sr) {
//                            return grc.sign(sr);
//                        }
//                    };
//
//                    wallet.registerIdentity(identity, gf);
//                }
            }
        }

        @Command(name = "restore")
        static class Restore extends Create {

            @Option(names = "--all-with-blkzn", description = "Restore all keys using BlkZn")
            boolean all = false;

            @Override
            public void execute() {
                super.execute();

                if (all) {
                    // TODO: This is not how it
                    System.out.println("We should create the subkeys");
                    identity.restoreAll();
                    identity.protocolCredentials.forEach((s, abstractPublicKeyProtocolConfiguration) -> {
                        abstractPublicKeyProtocolConfiguration.activeCredentials.forEach(abstractPublicKeyCredentials -> {
                            abstractPublicKeyCredentials.saveKeysToDir(idPath.toFile(), password);
                        });
                    });
                }
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
            @Option(names = "--alg", description = "PublicKey Algorithm", defaultValue = "rsa")
            String alg;

            @Option(names = "--alg-size", description = "PublicKey Algorithm Size", defaultValue = "3072")
            Integer algSize;

            @Option(names = "--hash", description = "Hash Algorithm", defaultValue = "sha")
            String hash;

            @Option(names = "--hash-size", description = "Hash Algorithm Size", defaultValue = "256")
            Integer hashSize;

            @Option(names = "--password", description = "Password to protect the key")
            String password = "";

            @Option(names = "--register", description = "Register the identity with BlkZn")
            boolean register = false;

            @Option(names = "--persist", description = "Persist the keys on disk")
            boolean persist = true;

            @Override
            public void execute() {
                KeyVault.Identity.SshProtocolConfiguration sshProtocolConfiguration = identity.createSshKeyConfiguration(alg, algSize, hash, hashSize);
                KeyVault.Identity.SshProtocolConfiguration.SshProtocolCredentials spc = sshProtocolConfiguration.create();

                if (register) {
                    sshProtocolConfiguration.register(spc);
                }

                if (persist) {
                    spc.persist(idPath);
                }
            }
        }

        @Command(name = "export")
        static class Export extends IdentitySubCommand {
            @Option(names = "--to-dir", description = "Target directory", defaultValue = "/tmp/")
            String toDir;

            @Override
            public void execute() {
                System.out.println("Exporting keys");
                //                spc.saveKeysToDir(idPath.toFile(), password);
                try {
                    // TODO: What is the init path?
                    init();
                    KeyVault.Identity.SshProtocolConfiguration spc = (KeyVault.Identity.SshProtocolConfiguration) this.identity.protocolCredentials.get(KeyVault.Identity.SshProtocolConfiguration.pcd);
                    Path toDirPath = Paths.get(toDir);
                    spc.activeCredentials.forEach(sshProtocolCredentials -> {
                        SshExporterBuilder builder = new SshExporterBuilder(sshProtocolCredentials.kp, toDirPath)
                                .setEmail(identity.id)
                                .setName(identity.name);

                        builder.new SshPrivateKeyExporter().export();
                        builder.new SshPublicKeyExporter().export();
                    });

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                System.out.println("Exported keys");
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

            @Option(names = "--register", description = "Register the identity with BlkZn")
            boolean register = false;

            @Option(names = "--persist", description = "Persist the keys on disk")
            boolean persist = true;

            @Override
            public void execute() {
                KeyVault.Identity.NostrProtocolConfiguration nostrKeyConfiguration = identity.createNostrKeyConfiguration();
                KeyVault.Identity.NostrProtocolConfiguration.NostrProtocolCredentials npc = nostrKeyConfiguration.create();

                if (register) {
                    nostrKeyConfiguration.register(npc);
                }

                if (persist) {
                    npc.persist(idPath);
                }
            }
        }

        @Command(name = "export")
        static class Export extends IdentitySubCommand {
            @Option(names = "--to-dir", description = "Target directory", defaultValue = "/tmp/")
            String toDir;

            @Override
            public void execute() {
                System.out.println("Exporting keys");
                //                spc.saveKeysToDir(idPath.toFile(), password);
                try {

                    // TODO: What is the init path?
                    init();
                    Path toDirPath = Paths.get(toDir);

                    KeyVault.Identity.NostrProtocolConfiguration npc = (KeyVault.Identity.NostrProtocolConfiguration) this.identity.protocolCredentials.get(KeyVault.Identity.NostrProtocolConfiguration.pcd);
                    npc.activeCredentials.forEach(nostrProtocolCredentials -> {
                        NostrExporterBuilder builder =
                                new NostrExporterBuilder(nostrProtocolCredentials.kp, toDirPath)
                                        .setEmail(identity.id);

                        builder.new NostrPublicKeyExporter().export();
                        builder.new NostrPrivateKeyExporter().export();

//                        nostrProtocolCredentials.exportPublicKey(
//                                toDirPath.resolve(nostrProtocolCredentials.getDefaultPublicKeyFileName()).toFile());
//                        nostrProtocolCredentials.exportPrivateKey(
//                                toDirPath.resolve(nostrProtocolCredentials.getDefaultPrivateKeyFileName()).toFile(),
//                                "NOT IN USE!"
//                        );
                    });

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                System.out.println("Exported keys");
            }
        }
    }


//    @Command(name = "opgp-keypair", mixinStandardHelpOptions = true, subcommands = {
//            OpenPGPProtocolModule.Create.class,
//            OpenPGPProtocolModule.UpLoad.class
//    })
//    static class OpenPGPProtocolModule {
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
//                KeyVault.Identity.OpenPGPProtocolConfiguration openPGPProtocolConfiguration = identity.registerPGPkey(alg, algSize, hash, hashSize);
//                KeyVault.Identity.OpenPGPProtocolConfiguration.OpenPGPProtocolCredentials credentials = openPGPProtocolConfiguration.createAndRegisterNewCredentials();
//                credentials.saveKeysToDir(idPath.toFile(), password);
//            }
//        }
//
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
//    }

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

    abstract static class WalletSubCommand implements Callable<Integer> {
        protected KeyVault wallet;
        protected Path seedPath;

        @Option(names = "--wallet-root", description = "The rood dir of the wallet", defaultValue = ".bzw")
        Path walletRoot;

        public void init() throws Exception {
            // Make wallet-root absolute if its does not start with .
            if (!(walletRoot.isAbsolute() || walletRoot.startsWith("."))) {
                walletRoot = Path.of(System.getProperty("user.home")).resolve(walletRoot);
            }

            seedPath = walletRoot.resolve("seed");

            if (seedPath.toFile().exists())
                wallet = KeyVault.fromSeedFile(seedPath.toFile());
        }

        abstract public void execute();

        @Override
        final public Integer call() throws Exception {
            init();
            execute();
            return 0;
        }
    }

    abstract static class IdentitySubCommand extends WalletSubCommand {
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
        protected KeyVault.Identity identity;

        @Option(names = "--id", description = "The identity", required = true)
        String id;

        @Override
        public void init() throws Exception {
            super.init();
            idPath = walletRoot.resolve(id);
            metaPath = idPath.resolve(IdentityMetaData.path);

            if (idPath.toFile().exists()) {
                ObjectMapper om = new ObjectMapper();
                IdentityMetaData metaData = om.readValue(metaPath.toFile(), IdentityMetaData.class);
                this.identity = wallet.new Identity(id, metaData.name);

                // Load the keys from disk
                this.identity.recallAll(idPath);
            }
        }
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
