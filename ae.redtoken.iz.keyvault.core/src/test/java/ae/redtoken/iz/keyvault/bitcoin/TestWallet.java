package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.BitcoinMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMaster;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.BitcoinAvatarService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class TestWallet extends LTBCMainTestCase {

    public static BitcoinAvatarService fromWatchingKey(Network network, DeterministicKey watchKey, Collection<ScriptType> outputScriptTypes, BitcoinMasterService masterService) {
        List<DeterministicKeyChain> chains = outputScriptTypes.stream()
                .map(type ->
                        DeterministicKeyChain.builder()
                                .watch(watchKey)
                                .outputScriptType(type)
                                .build())
                .toList();
        return new BitcoinAvatarService(network, KeyChainGroup.builder(network).chains(chains).build(), masterService);
    }

    public static class Identity {
        static Map<String, Class<? extends Protocol>> protocolFacktory = new HashMap<>();

        static {
            protocolFacktory.put(BitcoinProtocol.protocolId, BitcoinProtocol.class);
        }

        public final String id;
        public final Map<String, Protocol> protocols = new HashMap<>();

        Identity(String id) {
            this.id = id;
        }

        @SneakyThrows
        Protocol getProtocol(String protocolId) {
            if (!protocols.containsKey(protocolId)) {
                Protocol protocol = protocolFacktory.get(protocolId).getConstructor().newInstance();
                protocols.put(protocolId, protocol);
            }
            return protocols.get(protocolId);
        }
    }

    static abstract class Protocol {
        abstract String getProtocolId();
    }

    public static class ConfigurationHelper {
        @SneakyThrows
        public static String toJSON(Object object) {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(object);
        }

        static byte[] hash(Object object) {
            return WalletHelper.mangle(toJSON(object));
        }
    }

    public record BitcoinConfiguration(Network network, BitcoinKeyGenerator keyGenerator,
                                       Collection<ScriptType> scriptTypes) {
        enum BitcoinKeyGenerator {
            BIP32(KeyChainGroupStructure.BIP32),
            BIP43(KeyChainGroupStructure.BIP43);

            public final KeyChainGroupStructure kcgs;

            BitcoinKeyGenerator(KeyChainGroupStructure kcgs) {
                this.kcgs = kcgs;
            }
        }
    }

    public static class BitcoinProtocol extends Protocol {
        public static String protocolId = "bitcoin";

        Collection<BitcoinConfiguration> configurations = new ArrayList<>();

        public BitcoinProtocol() {
        }

        @Override
        String getProtocolId() {
            return protocolId;
        }
    }

    @SneakyThrows
    @Test
    void testSendMoney() {
        RegTestParams params = RegTestParams.get();
        ScriptType scriptType = ScriptType.P2PKH;

        String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
//        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 512, "");

        /**
         *
         *  Login witch is called connect...
         *
         *  1. The external device creates the Connector, the KeyMaster connects to the Connector spawning the KeyMasterAvatar.
         *      The Avatar is configured with a set of Identities, including the primary identity, and with them a set of protocols with configurations.
         *      All of this is a Session, and the configurations are Services.
         *
         *  2. The Avatar can then Spawn incarnations with a subset of its abilities.
         *
         */

        List<ScriptType> scriptTypes = List.of(scriptType);
        KeyVault kv = new KeyVault(params.network(), ds);

        // TODO, this is a bit of a hack we crate a kit and then add a second wallet, discarding the first
        Path tmpDir = Files.createTempDirectory("test_");
        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
        kit.connectToLocalHost();
        kit.startAsync().awaitRunning();

        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint();
        KeyMaster keyMaster = new KeyMaster(kv);

        Identity identity = new Identity("bob@teahouse.wl");
        keyMaster.getIdentities().add(identity);

        BitcoinProtocol bp = (BitcoinProtocol) identity.getProtocol(BitcoinProtocol.protocolId);
        bp.configurations.add(new BitcoinConfiguration(params.network(), BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes));

        KeyMasterAvatar avatar = spawnPoint.connect(keyMaster);

        BitcoinProtocol bp2 = (BitcoinProtocol) avatar.getDefaultIdentity().getProtocol(BitcoinProtocol.protocolId);
        BitcoinConfiguration bitcoinConfiguration = bp2.configurations.stream().findFirst().orElseThrow();

        // Retrieve the WatchingKey to setup the wallet
        keyMaster.createBitcoinMasterService(identity, bitcoinConfiguration);
        BitcoinMasterService aliceBitcoinMasterService = keyMaster.bmsm.get(identity.id);

        // Let's do the avatar
        KeyMasterAvatar.IdentityAvatar ia = avatar.new IdentityAvatar(avatar.getDefaultIdentity());
        KeyMasterAvatar.IdentityAvatar.BitcoinProtocolAvatar bpa = ia.new BitcoinProtocolAvatar();
        bpa.createBitcoinAvatarService(aliceBitcoinMasterService);

//        GetWatchingKeyAccept wk = aliceBitcoinMasterService.getWatchingKey();
//        DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey, params.network());
//        BitcoinAvatarService aliceBitcoinAvatarService = fromWatchingKey(bitcoinConfiguration.network, watchingKey, wk.scriptTypes, aliceBitcoinMasterService);
        BitcoinAvatarService aliceBitcoinAvatarService = bpa.createBitcoinAvatarService(aliceBitcoinMasterService);

        kit.peerGroup().addWallet(aliceBitcoinAvatarService.wallet);
        kit.chain().addWallet(aliceBitcoinAvatarService.wallet);

        Address address = aliceBitcoinAvatarService.wallet.freshReceiveAddress();

        // Make sure the wallet is empty
        Assertions.assertEquals(Coin.valueOf(0), aliceBitcoinAvatarService.wallet.getBalance());

        ltbc.sendTo(address.toString(), 1.0);
        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        // Make sure we got the coins
        Assertions.assertEquals(Coin.valueOf(1, 0), aliceBitcoinAvatarService.wallet.getBalance());

        // Bob creates an address for Alice
        Path bobsTempDir = Files.createTempDirectory("test2_");
        WalletAppKit bobsKit = new WalletAppKit(params, bobsTempDir.toFile(), "test");
        bobsKit.connectToLocalHost();
        bobsKit.startAsync().awaitRunning();

        Address bobsAddress = bobsKit.wallet().freshReceiveAddress();

        // The Avatar creates a SR
        SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
        sr.signInputs = false;
        aliceBitcoinAvatarService.wallet.completeTx(sr);
//        aliceBitcoinAvatarService.masterService.zsignTransaction(sr.tx);


        // The Avatar reads the response off wire and sends it out on network
        Transaction tx3 = aliceBitcoinAvatarService.signTransaction(sr.tx);
        kit.peerGroup().broadcastTransaction(tx3);

        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        Assertions.assertEquals(92977300, aliceBitcoinAvatarService.wallet.getBalance().longValue());
        Assertions.assertEquals(7000000, bobsKit.wallet().getBalance().longValue());
//        System.out.println(ww.getBalance());
//        System.out.println(kit2.wallet().getBalance());

        System.out.println("The END");
    }


    @Test
    void testConf() {
        BitcoinConfiguration conf = new BitcoinConfiguration(
                RegTestParams.get().network(),
                BitcoinConfiguration.BitcoinKeyGenerator.BIP32,
                List.of(ScriptType.P2PKH, ScriptType.P2PK));

        System.out.println(ConfigurationHelper.toJSON(conf));

        byte[] hash = ConfigurationHelper.hash(conf);
    }
}
