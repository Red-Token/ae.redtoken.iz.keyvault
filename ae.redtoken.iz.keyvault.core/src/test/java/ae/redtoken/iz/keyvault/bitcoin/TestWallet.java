package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.*;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.BitcoinAvatarService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.protocol.*;
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

        KeyMasterRunnable kmr = new KeyMasterRunnable(keyMaster);
        Thread kmt = new Thread(kmr);
        kmt.start();

        KeyMasterAvatarRunnable kmar = new KeyMasterAvatarRunnable() {
            @SneakyThrows
            @Override
            public void run() {
                this.masterRunnable = kmr;
                System.out.println("RUNNING");

                IKeyMaster proxy = createProxy(new String[0], IKeyMaster.class);

                String defaultId = proxy.getDefaultId();

                System.out.println(defaultId);

                String[] address2 = {defaultId};
                IIdentity ip = createProxy(address2, IIdentity.class);

                Set<String> childIds = ip.getChildIds();
                IStackedService bp = createProxy(new String[]{defaultId, childIds.iterator().next()}, IStackedService.class);
                Set<String> childIds1 = bp.getChildIds();
                IBitcoinConfigurationStackedService bitcoinService = createProxy(new String[]{defaultId, childIds.iterator().next(), childIds1.iterator().next()}, IBitcoinConfigurationStackedService.class);
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
//        aliceBitcoinAvatarService.masterService.zsignTransaction(sr.tx);


                // The Avatar reads the response off wire and sends it out on network
                Transaction tx3 = aliceBitcoinAvatarService.signTransaction(sr.tx);
                kit.peerGroup().broadcastTransaction(tx3);

                ltbc.mine(6);

                // Wait for the wallet to sync up.
                Thread.sleep(1000);

                System.out.println(aliceBitcoinAvatarService.wallet.getBalance().longValue());
                Assertions.assertEquals(92977300, aliceBitcoinAvatarService.wallet.getBalance().longValue());
//                Assertions.assertEquals(7000000, bobsKit.wallet().getBalance().longValue());

                System.out.println("SDFSDFSDF");

            }
        };

        Thread kmat = new Thread(kmar);
        kmat.start();
        kmat.join();

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

        // TODO, this is a bit of a hack we crate a kit and then add a second wallet, discarding the first
        Path tmpDir = Files.createTempDirectory("test_");
        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
        kit.connectToLocalHost();
        kit.startAsync().awaitRunning();

        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint();

        KeyMasterAvatar avatar = spawnPoint.connect(keyMaster);
        KeyMasterAvatar.IdentityAvatar identityAvatar = avatar.getDefaultIdentity();
        KeyMasterAvatar.IdentityAvatar.BitcoinProtocolAvatar bpa = identityAvatar.new BitcoinProtocolAvatar();

//        BitcoinProtocolStackedService bp2 = (BitcoinProtocolStackedService) avatar.getDefaultIdentity().getProtocol(BitcoinProtocolStackedService.PROTOCOL_ID);
//        BitcoinConfiguration bitcoinConfiguration = bp2.configurations.stream().findFirst().orElseThrow();

        // Retrieve the WatchingKey to setup the wallet
        keyMaster.createBitcoinMasterService(identity, bitconf);
        BitcoinMasterService aliceBitcoinMasterService = keyMaster.bmsm.get(identity.id);

        // Let's do the avatar
//        KeyMasterAvatar.IdentityAvatar ia = avatar.new IdentityAvatar(avatar.getDefaultIdentity());
//        KeyMasterAvatar.IdentityAvatar.BitcoinProtocolAvatar bpa = ia.new BitcoinProtocolAvatar();
//        bpa.createBitcoinAvatarService(aliceBitcoinMasterService);

//        GetWatchingKeyAccept wk = aliceBitcoinMasterService.getWatchingKey();
//        DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey, params.network());
//        BitcoinAvatarService aliceBitcoinAvatarService = fromWatchingKey(bitcoinConfiguration.network, watchingKey, wk.scriptTypes, aliceBitcoinMasterService);
        BitcoinAvatarService aliceBitcoinAvatarService = KeyMasterAvatar.IdentityAvatar.BitcoinProtocolAvatar.createBitcoinAvatarService(aliceBitcoinMasterService);

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


//        // The Avatar creates a SR
//        SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
//        sr.signInputs = false;
//        aliceBitcoinAvatarService.wallet.completeTx(sr);
////        aliceBitcoinAvatarService.masterService.zsignTransaction(sr.tx);
//
//
//        // The Avatar reads the response off wire and sends it out on network
//        Transaction tx3 = aliceBitcoinAvatarService.signTransaction(sr.tx);
//        kit.peerGroup().broadcastTransaction(tx3);
//
//        ltbc.mine(6);
//
//        // Wait for the wallet to sync up.
//        Thread.sleep(1000);
//
//        Assertions.assertEquals(92977300, aliceBitcoinAvatarService.wallet.getBalance().longValue());
//        Assertions.assertEquals(7000000, bobsKit.wallet().getBalance().longValue());
//        System.out.println(ww.getBalance());
//        System.out.println(kit2.wallet().getBalance());

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
