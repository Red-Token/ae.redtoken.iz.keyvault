package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.*;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.*;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.BitcoinAvatarService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatar;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import ae.redtoken.iz.keyvault.bitcoin.test.TestKeyMasterAvatarRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class TestWallet extends LTBCMainTestCase {

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

    @SneakyThrows
    @Test
    void testSendMoney() {
        RegTestParams params = RegTestParams.get();
        BitcoinNetwork network = BitcoinNetwork.REGTEST;
        ScriptType scriptType = ScriptType.P2PKH;

        // Bob creates an address for Alice
        Path bobsTempDir = Files.createTempDirectory("test2_");
        WalletAppKit bobsKit = new WalletAppKit(params, bobsTempDir.toFile(), "test");
        bobsKit.connectToLocalHost();
        bobsKit.startAsync().awaitRunning();

        Address bobsAddress = bobsKit.wallet().freshReceiveAddress();

        /*
         * Fase 1 we create a ds and add it to the KeyVault, from there we create the KeyMaster and configure an identity, and a bitcoin protocol service.
         */

        String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");

        List<ScriptType> scriptTypes = List.of(scriptType);
        KeyVault kv = new KeyVault(network, ds);

        KeyMasterStackedService keyMaster = new KeyMasterStackedService(kv);
        IdentityStackedService identity = new IdentityStackedService(keyMaster, "bob@teahouse.wl");
        BitcoinProtocolStackedService bp = new BitcoinProtocolStackedService(identity);
        BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
        BitcoinConfigurationStackedService bc = new BitcoinConfigurationStackedService(bp, bitconf);

        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint();
        KeyMasterAvatar avatar = spawnPoint.connect(keyMaster);

        KeyMasterRunnable kmr = new KeyMasterRunnable(keyMaster);
        Thread kmt = new Thread(kmr);
        kmt.start();

        TestKeyMasterAvatarRunnable kmar = new TestKeyMasterAvatarRunnable() {

            @SneakyThrows
            public void runTest() {
                this.masterRunnable = kmr;
                System.out.println("RUNNING");

                IKeyMaster proxy = createProxy(new String[0], IKeyMaster.class);
                String defaultId = proxy.getDefaultId();

                IStackedService bp = createProxy(new String[]{defaultId, BitcoinProtocolStackedService.PROTOCOL_ID}, IStackedService.class);
                String defaultProtocolConfiguration = bp.getDefaultId();
                IBitcoinConfiguration bitcoinService = createProxy(new String[]{defaultId, BitcoinProtocolStackedService.PROTOCOL_ID, defaultProtocolConfiguration}, IBitcoinConfiguration.class);
                BitcoinAvatarService aliceBitcoinAvatarService = KeyMasterAvatar.IdentityAvatar.BitcoinProtocolAvatar.createBitcoinAvatarService(bitcoinService);

                Path tmpDir = Files.createTempDirectory("testzxc_");
                WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
                kit.connectToLocalHost();
                kit.startAsync().awaitRunning();

                kit.peerGroup().addWallet(aliceBitcoinAvatarService.wallet);
                kit.chain().addWallet(aliceBitcoinAvatarService.wallet);

                Address bitcoinAddress = aliceBitcoinAvatarService.wallet.freshReceiveAddress();

                // Make sure the wallet is empty
                Assertions.assertEquals(Coin.valueOf(0), aliceBitcoinAvatarService.wallet.getBalance());

                ltbc.sendTo(bitcoinAddress.toString(), 1.0);
                ltbc.mine(6);

                // Wait for the wallet to sync up.
                Thread.sleep(1000);

                // Make sure we got the coins
                Assertions.assertEquals(Coin.valueOf(1, 0), aliceBitcoinAvatarService.wallet.getBalance());

                // The Avatar creates a SR
                SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
                sr.signInputs = false;
                aliceBitcoinAvatarService.wallet.completeTx(sr);

                // The Avatar reads the response off wire and sends it out on network
                Transaction tx3 = aliceBitcoinAvatarService.signTransaction(sr.tx);
                kit.peerGroup().broadcastTransaction(tx3);

                ltbc.mine(6);

                // Wait for the wallet to sync up.
                Thread.sleep(1000);

                System.out.println(aliceBitcoinAvatarService.wallet.getBalance().longValue());
                Assertions.assertEquals(92977300, aliceBitcoinAvatarService.wallet.getBalance().longValue());

                System.out.println("SDFSDFSDF");
            }
        };

        kmar.runTest();

        Assertions.assertEquals(7000000, bobsKit.wallet().getBalance().longValue());

        /*
         *  Fase 2, we log in to the Avatar, the Avatar detects the default identity, detects the services and allows us to check out a BitcoinAvatarService.
         *
         * This uses messages to connect to KeyMaster, and everything should be passed as messages.
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

        System.out.println("The END");
    }


    @Test
    void testConf() {
        BitcoinConfiguration conf = new BitcoinConfiguration(
                BitcoinNetwork.REGTEST,
                BitcoinConfiguration.BitcoinKeyGenerator.BIP32,
                List.of(ScriptType.P2PKH, ScriptType.P2PK));

        System.out.println(ConfigurationHelper.toJSON(conf));

        byte[] hash = ConfigurationHelper.hash(conf);
    }
}
