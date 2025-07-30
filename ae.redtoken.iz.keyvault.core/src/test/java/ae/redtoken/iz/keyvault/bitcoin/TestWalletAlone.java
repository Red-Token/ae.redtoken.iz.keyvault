package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.SystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.SendRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class TestWalletAlone extends LTBCMainTestCase {


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

        List<ScriptType> scriptTypes = List.of(scriptType);

//        String password = "Open Sesame!";
//        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(password);

        // Create the KeyMasterExecutor


//        SystemAvatar systemAvatar = spawnPoint.spawn();

        Thread.sleep(1000);

        // Connect to the system Avatar that has just spawned
        KeyMasterAvatarConnector ac = new KeyMasterAvatarConnector(new DatagramSocket(), new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT));

        KeyMasterAvatarConnector.KeyMasterAvatarService kmas = ac.new KeyMasterAvatarService();
        KeyMasterAvatarConnector.IdentityAvatarService ias = ac.new IdentityAvatarService(kmas.subId(kmas.service.getDefaultId()));
        KeyMasterAvatarConnector.BitcoinProtocolAvatarService bpas = ac.new BitcoinProtocolAvatarService(ias.subId(ias.service.getDefaultId()));
        KeyMasterAvatarConnector.BitcoinConfigurationAvatarService bcas = ac.new BitcoinConfigurationAvatarService(bpas.subId(bpas.service.getDefaultId()));

        Path tmpDir = Files.createTempDirectory("testzxc_");
        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
        kit.connectToLocalHost();
        kit.startAsync().awaitRunning();

        kit.peerGroup().addWallet(bcas.wallet);
        kit.chain().addWallet(bcas.wallet);

        Address bitcoinAddress = bcas.wallet.freshReceiveAddress();

        // Make sure the wallet is empty
        Assertions.assertEquals(Coin.valueOf(0), bcas.wallet.getBalance());

        ltbc.sendTo(bitcoinAddress.toString(), 1.0);
        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        // Make sure we got the coins
        Assertions.assertEquals(Coin.valueOf(1, 0), bcas.wallet.getBalance());

        // The Avatar creates a SR
        SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
        sr.signInputs = false;
        bcas.wallet.completeTx(sr);

        // The Avatar reads the response off wire and sends it out on network
//        Transaction tx3 = bitcoinAvatarService.signTransaction(sr.tx);
        Transaction tx3 = bcas.signTransaction(sr.tx);
        kit.peerGroup().broadcastTransaction(tx3);

        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        System.out.println(bcas.wallet.getBalance().longValue());
        Assertions.assertEquals(92977300, bcas.wallet.getBalance().longValue());
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
