package ae.redtoken.iz.keyvault;

import ae.redtoken.lib.PublicKeyProtocolMetaData;
import ae.redtoken.util.WalletHelper;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Logger;

public class Identity {
    private static final Logger log = Logger.getLogger(Identity.class.getName());

    // TODO merge these two
    public SshProtocolConfiguration createSshKeyConfiguration(String pubAlg, int pubBits) {
        return new SshProtocolConfiguration(this, new ProtocolMetaData(new PublicKeyProtocolMetaData(pubAlg, pubBits), 0));
    }

    public OpenPGPProtocolConfiguration createOpenPGPKeyConfiguration(String pubAlg, int pubBits, long creationTime) {
        return new OpenPGPProtocolConfiguration(this, new ProtocolMetaData(new PublicKeyProtocolMetaData(pubAlg, pubBits), creationTime));
    }

    public NostrProtocolConfiguration createNostrKeyConfiguration() {
        return new NostrProtocolConfiguration(this, new ProtocolMetaData(new PublicKeyProtocolMetaData(), 0));
    }

    //        public OpenPGPProtocolConfiguration registerPGPkey(String pubAlg, int pubBits, String hashAlg, int hashBits) {
//            return new OpenPGPProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
//        }

//        public OpenPGPProtocolConfiguration restorePgpProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//            return new OpenPGPProtocolConfiguration(metaData);
//        }

//        public X509ProtocolConfiguration registerX509Key(String pubAlg, int pubBits, String hashAlg, int hashBits) {
//            return new X509ProtocolConfiguration(new PublicKeyProtocolMetaData(pubAlg, pubBits, hashAlg, hashBits));
//        }
//
//        public X509ProtocolConfiguration restoreX509ProtocolConfiguration(PublicKeyProtocolMetaData metaData) {
//            return new X509ProtocolConfiguration(metaData);
//        }

    static final Map<String, Class<? extends AbstractPublicKeyProtocolConfiguration<? extends AbstractImplementedPublicKeyCredentials>>> protocolMap = new HashMap<>();

    final String name;
    final protected String id;
    final DeterministicSeed seed;

    public Identity(KeyVault keyVault, String id, String name) {
        this.id = id;
        this.seed = WalletHelper.createSubSeed(keyVault.seed, id);
        this.name = name;
    }

    private void recallProtocol(File protocolDir) throws Exception {

        Constructor<?>[] declaredConstructors = protocolMap.get(protocolDir.getName()).getDeclaredConstructors();

        Constructor<? extends AbstractPublicKeyProtocolConfiguration<? extends AbstractImplementedPublicKeyCredentials>> constructor
                = protocolMap.get(protocolDir.getName()).getDeclaredConstructor(Identity.class, File.class);

        Arrays.stream(Objects.requireNonNull(protocolDir.listFiles()))
                .filter(file -> file.getName().endsWith(".json"))
                .forEach(file -> {
                            try {
                                constructor.newInstance(this, file);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
    }

    void recallAll(Path idPath) {
        File idDir = idPath.toFile();

        if (!idDir.exists() || !idDir.isDirectory()) {
            log.warning("Path does not exist or is not a directory");
            return;
        }

        Arrays.stream(Objects.requireNonNull(idDir.listFiles()))
                .filter(file -> protocolMap.containsKey(file.getName()))
                .forEach(file -> {
                            try {
                                recallProtocol(file);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
    }

//    void restoreAll() {
//            BlkZnEntity blkZnEntity = getController().getBlkZnEntity();
//            Registration registration = blkZnEntity.getActiveRegistration();
//
//            if (registration == null) {
//                log.warn("FIXME: Trying to restore while registration is null we could have a unclean directory here");
//                return;
//            }

//            registration.opgp.forEach(gme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(gme);
//                OpenPGPProtocolConfiguration openPGPProtocolConfiguration =
//                        restorePgpProtocolConfiguration(metaData);
//                openPGPProtocolConfiguration.restoreKey(gme, 1000);
//            });

//            registration.ssh.forEach(sme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(sme);
//                SSHProtocolConfiguration sshProtocolConfiguration =
//                        new SSHProtocolConfiguration(metaData);
//                sshProtocolConfiguration.restoreKey(sme.hash.getValue(), 1000);
//            });

//            registration.x509.forEach(xme -> {
//                PublicKeyProtocolMetaData metaData = PublicKeyProtocolMetaData.from(xme);
//                X509ProtocolConfiguration x509ProtocolConfiguration =
//                        new X509ProtocolConfiguration(metaData);
//                x509ProtocolConfiguration.restoreKey(xme, 1000);
//            });
//    }

    public Map<String, AbstractPublicKeyProtocolConfiguration<? extends AbstractImplementedPublicKeyCredentials>> protocolCredentials = new HashMap<>();
}
