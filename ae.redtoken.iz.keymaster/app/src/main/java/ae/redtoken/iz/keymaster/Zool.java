package ae.redtoken.iz.keymaster;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.protocolls.ssh.SshAgent;

public class Zool {

    static String mainX() {
        try {

            System.out.println("SFSDFSDFSD");

            Security.removeProvider("BC");
            Security.addProvider(new BouncyCastleProvider());

            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider: " + provider.getName());
                for (Provider.Service service : provider.getServices()) {
                    if (service.getType().equals("KeyPairGenerator")) {
                        System.out.println("  Algorithm: " + service.getAlgorithm());
                    }
                }
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            KeyPairGenerator kpg3 = KeyPairGenerator.getInstance("RSA", "BC");

            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
            KeyVault kv = new KeyVault(ds);

            RegTestParams params = RegTestParams.get();
            BitcoinNetwork network = BitcoinNetwork.REGTEST;
            ScriptType scriptType = ScriptType.P2PKH;
            List<ScriptType> scriptTypes = List.of(scriptType);

            BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);

            ObjectMapper om =  new ObjectMapper();
            om.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
            String val = om.writeValueAsString(bitconf);
            System.out.println(val);

            SshConfiguration sshConfiguration = new SshConfiguration(SshKeyType.ED25519, 255);
            val = om.writeValueAsString(sshConfiguration);
            System.out.println(val);

            NostrConfiguration nc = new NostrConfiguration();
            val = om.writeValueAsString(nc);

            System.out.println(val);


            String email = "bob@teahouse.wl";
            String password = "Open Sesame!";

            IZKeyMaster km = new IZKeyMaster(kv, email, network, scriptTypes);

            InetSocketAddress address = new InetSocketAddress("192.168.100.14", AvatarSpawnPoint.SPAWN_PORT);
            km.login(password, address);


//            DatagramSocket socket = new DatagramSocket();
//
//            SocketAddress address = new InetSocketAddress("192.168.100.14", 15000);
//            byte[] packet = "Hello".getBytes();
//
//            socket.send(new DatagramPacket(packet, packet.length, address));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        return "ZZZZZ";
    }

}
