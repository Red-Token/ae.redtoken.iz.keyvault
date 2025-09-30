package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.UdpRequestProcessor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import lombok.SneakyThrows;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.List;

public class IZKeyMaster {
    public NostrConfigurationStackedService ncss;
    final KeyMasterExecutor kmr;

    @SneakyThrows
    public IZKeyMaster(KeyVault kv, String email, BitcoinNetwork network, List<ScriptType> scriptTypes) {
        // Configure the KM
        KeyMasterStackedService kmss = new KeyMasterStackedService(kv);

        IdentityStackedService identity = new IdentityStackedService(kmss, email);

        // Create a bitcoin / crypto protocol stack
        BitcoinProtocolStackedService bpss = new BitcoinProtocolStackedService(identity);
        BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
        BitcoinConfigurationStackedService bcss = new BitcoinConfigurationStackedService(bpss, bitconf);

        // Nostr
        NostrProtocolStackedService npss = new NostrProtocolStackedService(identity);
        NostrConfiguration nc = new NostrConfiguration();
        this.ncss = new NostrConfigurationStackedService(npss, nc);

        // Create the SS in the KM
        SshProtocolStackedService spss = new SshProtocolStackedService(identity);
        SshConfiguration sc = new SshConfiguration(SshKeyType.ED25519, 255);
        SshConfigurationStackedService scss = new SshConfigurationStackedService(spss, sc);

        // Create the KeyMasterExecutor
        this.kmr = new KeyMasterExecutor(kmss);
    }

    @SneakyThrows
    public void login(String password, InetSocketAddress avatarSocketAddress) {
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
    }
}
