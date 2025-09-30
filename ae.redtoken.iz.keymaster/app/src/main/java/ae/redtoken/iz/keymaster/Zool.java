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
//
//            System.out.println("SFSDFSDFSD");

            Security.removeProvider("BC");
            Security.addProvider(new BouncyCastleProvider());

            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
            KeyVault kv = new KeyVault(ds);

//            RegTestParams params = RegTestParams.get();
            BitcoinNetwork network = BitcoinNetwork.REGTEST;
            ScriptType scriptType = ScriptType.P2PKH;
            List<ScriptType> scriptTypes = List.of(scriptType);

            String email = "bob@teahouse.wl";
            String password = "Open Sesame!";

            IZKeyMaster km = new IZKeyMaster(kv, email, network, scriptTypes);

            InetSocketAddress address = new InetSocketAddress("192.168.100.14", AvatarSpawnPoint.SPAWN_PORT);
            km.login(password, address);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return "ZZZZZ";
    }

}
