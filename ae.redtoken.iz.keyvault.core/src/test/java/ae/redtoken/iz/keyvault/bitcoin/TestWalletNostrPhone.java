package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint2;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.IZSystemAvatar2;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector2;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.protocolls.ssh.agent.IZSshAgent2;
import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.List;

public class TestWalletNostrPhone extends LTBCMainTestCase {


    /***
     *
     *  It's called testSendMoney, but in reality it does a lot more
     *
     *  It kreates a keymaster, a keymasteravatar, creates the SSH, BTC and Nostr services
     *  And send a message over nostr, log in via SSH, and send money to bob
     *
     *
     */
    @SneakyThrows
    @Test
    void testSendMoney() {
        Security.addProvider(new BouncyCastleProvider());

//        long now = System.currentTimeMillis() / 1000;

        RegTestParams params = RegTestParams.get();
//        BitcoinNetwork network = BitcoinNetwork.REGTEST;
//        ScriptType scriptType = ScriptType.P2PKH;

        // Bob creates an address for Alice
        Path bobsTempDir = Files.createTempDirectory("test2_");
        WalletAppKit bobsKit = new WalletAppKit(params, bobsTempDir.toFile(), "test");
        bobsKit.connectToLocalHost();
        bobsKit.startAsync().awaitRunning();

//        Address bobsAddress = bobsKit.wallet().freshReceiveAddress();

        /*
         * Phase 1 we create a ds and add it to the KeyVault, from there we create the KeyMaster and configure an identity, and a bitcoin protocol service.
         */
//        String password = "Open Sesame!";
        AvatarSpawnPoint2 spawnPoint = new AvatarSpawnPoint2(AvatarSpawnPoint.SPAWN_PORT, AvatarSpawnPoint.SERVICE_PORT);

//        String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
//        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
//        KeyVault kv = new KeyVault(ds);
//
//        List<ScriptType> scriptTypes = List.of(scriptType);

        // Connect keymaster to the Avatar
        final InetSocketAddress avatarSocketAddress = new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SPAWN_PORT);
        String email = "bob@teahouse.wl";

//        IZKeyMaster2 km = new IZKeyMaster2(kv, email, network, scriptTypes);
//        km.login(avatarSocketAddress);

//        AvatarSpawnPoint spawnPoint;
        IZSystemAvatar2 systemAvatar = spawnPoint.spawn();

        Thread.sleep(1000);

        // Connect to the system Avatar that has just spawned
        KeyMasterAvatarConnector2 avatar = new KeyMasterAvatarConnector2(new DatagramSocket(), new InetSocketAddress(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT));

        KeyMasterAvatarConnector2.KeyMasterAvatarService kmas = avatar.new KeyMasterAvatarService();
        KeyMasterAvatarConnector2.IdentityAvatarService ias = avatar.new IdentityAvatarService(kmas.subId(kmas.service.getDefaultId()));

        /// This is the actual test
        /// First we create the services

        //TODO: This is a bit of a hack, should we do this dynamically?

        // Bitcoin
//        KeyMasterAvatarConnector2.BitcoinProtocolAvatarService bpas = avatar.new BitcoinProtocolAvatarService(ias.subId(BitcoinProtocolStackedService.PROTOCOL_ID));
//        KeyMasterAvatarConnector2.BitcoinConfigurationAvatarService bcas = avatar.new BitcoinConfigurationAvatarService(bpas.subId(bpas.service.getDefaultId()));
//
//        // Nostr
//        KeyMasterAvatarConnector2.NostrProtocolAvatarService npas = avatar.new NostrProtocolAvatarService(ias.subId(NostrProtocolStackedService.PROTOCOL_ID));
//        KeyMasterAvatarConnector2.NostrConfigurationAvatarService ncas = avatar.new NostrConfigurationAvatarService(npas.subId(npas.service.getDefaultId()));

//        // SSH
//        KeyMasterAvatarConnector2.SshProtocolAvatarService spas = avatar.new SshProtocolAvatarService(ias.subId(SshProtocolStackedService.PROTOCOL_ID));
//        KeyMasterAvatarConnector2.SshConfigurationAvatarService scas = avatar.new SshConfigurationAvatarService(spas.subId(spas.service.getDefaultId()));

        /// This is the SSH test
        IZSshAgent2 IZSshAgent = new IZSshAgent2(AvatarSpawnPoint.HOSTNAME, AvatarSpawnPoint.SERVICE_PORT);

        /// Get the public key from the Avatar
//        SshProtocolMessages.SshGetPublicKeyAccept sshGetPublicKeyAccept = scas.service.getPublicKey();

        // Save the ssh key
        String alg = SshKeyType.ED25519.sshName;
        String keyString = String.format("%s %s %s", alg, IZSshAgent.sshGetPublicKeyAccept.pubKey(), email);
        System.out.println(keyString);

        FileOutputStream stream = new FileOutputStream(Path.of("/tmp/zool.pub").toFile());
        stream.write(keyString.getBytes(StandardCharsets.UTF_8));

        // SSHD
        Process ps2 = Runtime.getRuntime().exec(new String[]{"/sbin/sshd","-d","-f","/var/tmp/ssh/sshd_config","-D"});

        Thread t = new Thread(new Runnable() {
            @SneakyThrows
            @Override
            public void run() {
                BufferedReader br3 = new BufferedReader(new InputStreamReader(ps2.getErrorStream()));

                for(String line = br3.readLine();
                    line != null && !line.startsWith("Server listening on 0.0.0.0 port 10022.");
                    line = br3.readLine()) {
                    System.out.println(line);
                }
            }
        });

        t.start();
        t.join();

        // Do SSH command
        Process ps = Runtime.getRuntime().exec(new String[]{"ssh", "-p", "10022",  "localhost", "exit"}, new String[]{"SSH_AUTH_SOCK=/tmp/zool.sock"});
        ps.waitFor();

        BufferedReader br = new BufferedReader(new InputStreamReader(ps.getInputStream()));
        br.lines().toList().forEach(System.out::println);

        ps2.waitFor();
        BufferedReader br2 = new BufferedReader(new InputStreamReader(ps2.getInputStream()));
        br2.lines().toList().forEach(System.out::println);
        BufferedReader br3 = new BufferedReader(new InputStreamReader(ps2.getErrorStream()));
        br3.lines().toList().forEach(System.out::println);

        Assertions.assertEquals(0, ps.exitValue());


        // TODO: we should check if the agent closes the connection

        /// Ssh test done
//        // Nostr test
//
//        // Create the Nostr client
//        Client client = Client.getInstance();
//        DefaultRequestContext requestContext = new DefaultRequestContext();
//        requestContext.setRelays(TestNostr.RELAYS);
//        client.connect(requestContext);
//
//        NostrProtocolMessages.NostrDescribeMessageAccept describe = ncas.service.describe();
//        String[] result = describe.result();
//
//        NostrProtocolMessages.NostrGetPublicKeyAccept publicKey = ncas.service.getPublicKey();
//        PublicKey pk = new PublicKey(publicKey.pubKey());
//
//        // Create the testevent
//        final String testMessage = "He-Man";
//        TextNoteEvent nostrEvent = new TextNoteEvent(pk, List.of(), testMessage);
//        nostrEvent.update();
//
//        // Create a filter for the messages
//        Filters filters = Filters.builder().since(now).authors(List.of(pk)).kinds(List.of(Kind.valueOf(nostrEvent.getKind()))).build();
//        FilteredEventQueue nostrFilter = new FilteredEventQueue(filters);
//
//        client.send(nostrFilter.getReqMessage());
//
//        ObjectMapper om = new ObjectMapper();
//        // To KM we send
//        String s = om.writeValueAsString(nostrEvent);
//        NostrProtocolMessages.NostrSignEventAccept nostrSignEventAccept = ncas.service.signEvent(new NostrProtocolMessages.NostrSignEventRequest(s));
//
//        Thread.sleep(1000);
//
//        Signature signature = new Signature();
//        signature.setRawData(NostrUtil.hexToBytes(nostrSignEventAccept.eventWithSignature()));
//        signature.setPubKey(pk);
//        nostrEvent.setSignature(signature);
//
//        // Send out the message
//        client.send(new
//
//                EventMessage(nostrEvent));
//
//        Thread.sleep(1000);
//
//        IEvent take = nostrFilter.take();
//        Assertions.assertEquals(nostrEvent.getId(), take.getId());
//
//        Identity bobId = Identity.generateRandomIdentity();
//
//        String msg1 = "Hello Bob!";
//
//        NostrConfigurationStackedService tncss = km.ncss;
//        NostrProtocolMessages.NostrNip44EncryptEventAccept nostrNip44EncryptEventAccept = tncss.nip44Encrypt(new NostrProtocolMessages.NostrNip44EncryptRequest(pk.toHexString(), bobId.getPublicKey().toHexString(), msg1));
//
//        MessageCipher cipher = new MessageCipher44(bobId.getPrivateKey().getRawData(), pk.getRawData());
//        String msg1Dec = cipher.decrypt(nostrNip44EncryptEventAccept.encryptedMessage());
//
//        Assertions.assertEquals(msg1, msg1Dec);
//
//        String msg2 = "Hello Alice!";
//
//        String encrypt = cipher.encrypt(msg2);
//
//        NostrProtocolMessages.NostrNip44DecryptEventAccept nostrNip44DecryptEventAccept = tncss.nip44Decrypt(new NostrProtocolMessages.NostrNip44DecryptRequest(pk.toHexString(), bobId.getPublicKey().toHexString(), encrypt));
//
//        Assertions.assertEquals(msg2, nostrNip44DecryptEventAccept.message());
//
//        // Bitcoin test
//        Path tmpDir = Files.createTempDirectory("testzxc_");
//        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
//        kit.connectToLocalHost();
//        kit.startAsync().
//
//                awaitRunning();
//
//        kit.peerGroup().
//
//                addWallet(bcas.wallet);
//        kit.chain().
//
//                addWallet(bcas.wallet);
//
//        Address bitcoinAddress = bcas.wallet.freshReceiveAddress();
//
//        // Make sure the wallet is empty
//        Assertions.assertEquals(Coin.valueOf(0), bcas.wallet.getBalance());
//
//        ltbc.sendTo(bitcoinAddress.toString(), 1.0);
//        ltbc.mine(6);
//
//        // Wait for the wallet to sync up.
//        Thread.sleep(1000);
//
//        // Make sure we got the coins
//        Assertions.assertEquals(Coin.valueOf(1, 0), bcas.wallet.getBalance());
//
//        // The Avatar creates a SR
//        SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
//        sr.signInputs = false;
//        bcas.wallet.completeTx(sr);
//
//        // The Avatar reads the response off wire and sends it out on network
////        Transaction tx3 = bitcoinAvatarService.signTransaction(sr.tx);
//        Transaction tx3 = bcas.signTransaction(sr.tx);
//        kit.peerGroup().
//
//                broadcastTransaction(tx3);
//
//        ltbc.mine(6);
//
//        // Wait for the wallet to sync up.
//        Thread.sleep(1000);
//
//        System.out.println(bcas.wallet.getBalance().
//
//                longValue());
//        Assertions.assertEquals(92977300, bcas.wallet.getBalance().
//
//                longValue());
//        Assertions.assertEquals(7000000, bobsKit.wallet().
//
//                getBalance().
//
//                longValue());

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
