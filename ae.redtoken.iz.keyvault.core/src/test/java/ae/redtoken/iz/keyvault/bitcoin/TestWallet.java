package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.*;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.*;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.MasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Response;
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

import java.net.*;
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

        String password = "Open Sesame!";
        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(password);

        KeyMasterRunnable kmr = new KeyMasterRunnable(keyMaster);
        Thread kmt = new Thread(kmr);
        kmt.start();
        boolean running = true;

        Thread t = new Thread(() -> {
            try {
                Thread.sleep(1000);

                System.out.println("Lets roll");

                //Log in
                final DatagramSocket socket = new DatagramSocket();
                final InetSocketAddress address = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.PORT);

//                kmr.sender.address = address;
//                kmr.sender.socket = socket;

                kmr.sender = new MasterRunnable.DirectResponseSender<>() {
                    @SneakyThrows
                    @Override
                    public void sendResponse(Response response) {
                        byte[] data = mapper.writeValueAsBytes(response);
                        DatagramPacket packet = new DatagramPacket(data, data.length, address);
                        socket.send(packet);
//                        super.sendResponse(response);
                    }
                };

                DatagramPacket packet = new DatagramPacket(password.getBytes(), password.length(), address);
                socket.send(packet);

                while (running) {
                    byte[] data = new byte[1024];
                    DatagramPacket packet2 = new DatagramPacket(data, data.length);
                    socket.receive(packet2);
                    kmr.receiver.receiveRequest(Arrays.copyOfRange(packet2.getData(), 0, packet2.getLength()));
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }


        });


        t.start();

        KeyMasterAvatar avatar = spawnPoint.spawn();


        KeyMasterAvatar.KeyMasterAvatarService kmas = avatar.new KeyMasterAvatarService();
        KeyMasterAvatar.IdentityAvatarService ias = avatar.new IdentityAvatarService(kmas.subId(kmas.service.getDefaultId()));
        KeyMasterAvatar.BitcoinProtocolAvatarService bpas = avatar.new BitcoinProtocolAvatarService(ias.subId(ias.service.getDefaultId()));
        KeyMasterAvatar.BitcoinConfigurationAvatarService bcas = avatar.new BitcoinConfigurationAvatarService(bpas.subId(bpas.service.getDefaultId()));

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
