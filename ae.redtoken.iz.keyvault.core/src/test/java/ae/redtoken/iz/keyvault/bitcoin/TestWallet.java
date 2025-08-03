package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.*;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.*;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.SystemAvatar;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.testnostr.sss.TestNostr;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import nostr.api.NIP01;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.event.impl.TextNoteEvent;
import nostr.id.Identity;
import nostr.util.NostrUtil;
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
        String password = "Open Sesame!";
        AvatarSpawnPoint spawnPoint = new AvatarSpawnPoint(AvatarSpawnPoint.SPAWN_PORT, password, AvatarSpawnPoint.SERVICE_PORT);

        String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");

        List<ScriptType> scriptTypes = List.of(scriptType);
        KeyVault kv = new KeyVault(ds);

        KeyMasterStackedService keyMaster = new KeyMasterStackedService(kv);
        IdentityStackedService identity = new IdentityStackedService(keyMaster, "bob@teahouse.wl");
        BitcoinProtocolStackedService bpss = new BitcoinProtocolStackedService(identity);
        BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
        BitcoinConfigurationStackedService bcss = new BitcoinConfigurationStackedService(bpss, bitconf);
        NostrProtocolStackedService npss = new NostrProtocolStackedService(identity);
        NostrConfiguration nc = new NostrConfiguration();
        NostrConfigurationStackedService ncss = new NostrConfigurationStackedService(npss,nc);


        // Create the KeyMasterExecutor
        KeyMasterExecutor kmr = new KeyMasterExecutor(keyMaster);

        final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SPAWN_PORT);
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

//        AvatarSpawnPoint spawnPoint;
        SystemAvatar systemAvatar = spawnPoint.spawn();

        Thread.sleep(1000);

        // Connect to the system Avatar that has just spawned
        KeyMasterAvatarConnector avatar = new KeyMasterAvatarConnector(new DatagramSocket(), new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT));

        KeyMasterAvatarConnector.KeyMasterAvatarService kmas = avatar.new KeyMasterAvatarService();
        KeyMasterAvatarConnector.IdentityAvatarService ias = avatar.new IdentityAvatarService(kmas.subId(kmas.service.getDefaultId()));

        //TODO: This is a bit of a hack, should we do this dynamically?
        KeyMasterAvatarConnector.BitcoinProtocolAvatarService bpas = avatar.new BitcoinProtocolAvatarService(ias.subId(BitcoinProtocolStackedService.PROTOCOL_ID));
        KeyMasterAvatarConnector.BitcoinConfigurationAvatarService bcas = avatar.new BitcoinConfigurationAvatarService(bpas.subId(bpas.service.getDefaultId()));

        KeyMasterAvatarConnector.NostrProtocolAvatarService npas = avatar.new NostrProtocolAvatarService(ias.subId(NostrProtocolStackedService.PROTOCOL_ID));
        KeyMasterAvatarConnector.NostrConfigurationAvatarService ncas = avatar.new NostrConfigurationAvatarService(npas.subId(npas.service.getDefaultId()));

        NostrProtocolMessages.NostrDescribeMessageAccept describe = ncas.service.describe();
        String[] result = describe.result();

        NostrProtocolMessages.NostrGetPublicKeyAccept publicKey = ncas.service.getPublicKey();
        PublicKey pk = new PublicKey(publicKey.pubKey());

        Identity sender = Identity.generateRandomIdentity();
        NIP01<TextNoteEvent> nip01 = new NIP01<>(sender);

        // The NostrLord starts here
        NIP01<TextNoteEvent> note = nip01.createTextNoteEvent("SSSSSS");
        note.setSender(sender);
        TextNoteEvent nostrEvent = new TextNoteEvent(pk, List.of(), "He-Man");
        nostrEvent.update();

        ObjectMapper om = new ObjectMapper();
        // To KM we send
        String s = om.writeValueAsString(nostrEvent);
        NostrProtocolMessages.NostrSignEventAccept nostrSignEventAccept = ncas.service.signEvent(new NostrProtocolMessages.NostrSignEventRequest(s));

        Signature signature = new Signature();
        System.out.println(nostrSignEventAccept.eventWithSignature());
        signature.setRawData(NostrUtil.hexToBytes(nostrSignEventAccept.eventWithSignature()));
        signature.setPubKey(pk);
        nostrEvent.setSignature(signature);
        nostrEvent.update();

        System.out.println(om.writeValueAsString(nostrEvent));

        System.out.println(nostrEvent.toString());

        note.send(nostrEvent, TestNostr.RELAYS);

        // {"id":"676a472c8c9b1182067b0a3157110a73aa172d326312bf4d4fcd9c3eaba0f58d","kind":1,"content":"He-Man","pubkey":"1d45aa7ff76e24d3dff39c3e2011e48470cb569e4c7ac1750fd2e6bfa3ed60e2","created_at":1754230709,"tags":[],"sig":"2e3abe203eadb5187e6d782cfda5517918e0907fd5179b1406ae432f757fa2927b1a49ae9402ceb119c8b4340df800f4c9799c907b66daf1a07896ff9a818d3b"}

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
