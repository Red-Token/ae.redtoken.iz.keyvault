package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.NostrOverUdpRequestProcessor;
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
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector2;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrOverUdpReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrOverUdpSender;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.NostrRoute;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.SshKeyType;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.AvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.ServiceInvocationHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import nostr.base.PublicKey;
import nostr.id.Identity;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class IZKeyMaster2 {
    public NostrConfigurationStackedService ncss;
    public SshConfigurationStackedService scss;
    Identity identity = Identity.generateRandomIdentity();

    final KeyMasterExecutor kmr;

    @SneakyThrows
    public IZKeyMaster2(KeyVault kv, String email, BitcoinNetwork network, List<ScriptType> scriptTypes) {


        // Configure the KM
        KeyMasterStackedService kmss = new KeyMasterStackedService(kv);

        IdentityStackedService iss = new IdentityStackedService(kmss, email);

        // Create a bitcoin / crypto protocol stack
        BitcoinProtocolStackedService bpss = new BitcoinProtocolStackedService(iss);
        BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
        BitcoinConfigurationStackedService bcss = new BitcoinConfigurationStackedService(bpss, bitconf);

        // Nostr
        NostrProtocolStackedService npss = new NostrProtocolStackedService(iss);
        NostrConfiguration nc = new NostrConfiguration();
        this.ncss = new NostrConfigurationStackedService(npss, nc);

        // Create the SS in the KM
        SshProtocolStackedService spss = new SshProtocolStackedService(iss);
        SshConfiguration sc = new SshConfiguration(SshKeyType.ED25519, 255);
        this.scss = new SshConfigurationStackedService(spss, sc);

        // Create the KeyMasterExecutor
        this.kmr = new KeyMasterExecutor(kmss);
    }

//    protected <A> A createProxy(String[] address, Class<A> cls) {
//        ServiceInvocationHandler<T> handler = new ServiceInvocationHandler<>(address, this);
//        return (A) Proxy.newProxyInstance(AvatarConnector.class.getClassLoader(), new Class[]{cls}, handler);
//    }


    @SneakyThrows
    public void login(InetSocketAddress avatarSocketAddress) {
        final DatagramSocket socket = new DatagramSocket();
        socket.connect(avatarSocketAddress);

        Thread t2 = new Thread(new NostrOverUdpRequestProcessor(kmr, socket, identity));
        t2.start();

        // TODO Fix the login?
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(1000);

//                String pubkeyHex = identity.getPublicKey().toHexString();

                NostrOverUdpSender nous = new NostrOverUdpSender(socket, identity);

                NostrRoute route = new NostrRoute();
                route.socketAddress = avatarSocketAddress;

                Request request = new Request(1000, new String[0], "Let me in");
                ObjectMapper om = new ObjectMapper();
                nous.sendPacket(om.writeValueAsBytes(request), route);


//                //Log in
//                DatagramPacket packet = new DatagramPacket(pubkeyHex.getBytes(), pubkeyHex.length(), avatarSocketAddress);
//                socket.send(packet);

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        t.start();
    }
}
