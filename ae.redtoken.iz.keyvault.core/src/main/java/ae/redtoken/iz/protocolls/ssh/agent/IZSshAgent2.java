package ae.redtoken.iz.protocolls.ssh.agent;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.SshProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.KeyMasterAvatarConnector2;
import ae.redtoken.iz.protocolls.ssh.ClientClosedException;
import ae.redtoken.iz.protocolls.ssh.ISignAPI;
import ae.redtoken.iz.protocolls.ssh.SshAgent;
import ae.redtoken.iz.protocolls.ssh.SshAgentConnection;
import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class IZSshAgent2 {
    public SshProtocolMessages.SshGetPublicKeyAccept sshGetPublicKeyAccept;

    public final ExecutorService executor;
    public boolean run = true;

    @SneakyThrows
    static UnixSocketChannel nextClient(SshAgent agent) {
        return agent.server.accept();
    }


    @SneakyThrows
    public IZSshAgent2(String host, int port) {
        executor = Executors.newCachedThreadPool();

        // Connect to the system Avatar that has just spawned
        KeyMasterAvatarConnector2 avatar = new KeyMasterAvatarConnector2(new DatagramSocket(), new InetSocketAddress(host, port));

        KeyMasterAvatarConnector2.KeyMasterAvatarService kmas = avatar.new KeyMasterAvatarService();
        KeyMasterAvatarConnector2.IdentityAvatarService ias = avatar.new IdentityAvatarService(kmas.subId(kmas.service.getDefaultId()));

        /// This is the actual test
        /// First we create the services

        //TODO: This is a bit of a hack, should we do this dynamically?

        // SSH
        KeyMasterAvatarConnector2.SshProtocolAvatarService spas = avatar.new SshProtocolAvatarService(ias.subId(SshProtocolStackedService.PROTOCOL_ID));
        KeyMasterAvatarConnector2.SshConfigurationAvatarService scas = avatar.new SshConfigurationAvatarService(spas.subId(spas.service.getDefaultId()));

        /// Get the public key from the Avatar
        sshGetPublicKeyAccept = scas.service.getPublicKey();

        // Create the agent
        SshAgent agent = new SshAgent();

        executor.execute(() -> {
            while (run) {
                final UnixSocketChannel inChannel = nextClient(agent);

                log.atInfo().log("Agent connected");

                Thread connectionThread = new Thread(new Runnable() {
                    @SneakyThrows
                    @Override
                    public void run() {

                        // Create a connection
                        SshAgentConnection connection = new SshAgentConnection(inChannel);

                        connection.api = new ISignAPI() {
                            @SneakyThrows
                            @Override
                            public java.security.PublicKey getPublicKey() {

                                // Here we get the public key from the Avatar and convert it
                                AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(Base64.getDecoder().decode(sshGetPublicKeyAccept.pubKey()));
                                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricKeyParameter);

                                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                                java.security.PublicKey key = converter.getPublicKey(subjectPublicKeyInfo);
                                return key;
                            }

                            @Override
                            public byte[] sign(byte[] key, byte[] data) {

                                // Read the request on wire, send it over to the Avatar and onward for signing
                                SshProtocolMessages.SshSignEventRequest request = new SshProtocolMessages.SshSignEventRequest(key, data);
                                SshProtocolMessages.SshSignEventAccept sshSignEventAccept = scas.service.signEvent(request);

                                return sshSignEventAccept.signature();
                            }
                        };

                        // Very nicely hardcoded that we process no less than 3 requests from the ssh client
                        try {
                            while (true) {
                                connection.processNextToken();
                            }
                        } catch (ClientClosedException eof) {
                            log.atInfo().log("Agent closed");
                        }
                    }
                });

                connectionThread.start();
            }
        });


//        // Accept the connection to the agent
//        Thread agentThread = new Thread(new Runnable() {
//            @SneakyThrows
//            @Override
//            public void run() {
//                while (true) {
//
//                    UnixSocketChannel inChannel = agent.server.accept();
//
//                    log.atInfo().log("Agent connected");
//
//                    Thread connectionThread = new Thread(new Runnable() {
//                        @SneakyThrows
//                        @Override
//                        public void run() {
//
//                            // Create a connection
//                            SshAgentConnection connection = new SshAgentConnection(inChannel);
//
//                            connection.api = new ISignAPI() {
//                                @SneakyThrows
//                                @Override
//                                public java.security.PublicKey getPublicKey() {
//
//                                    // Here we get the public key from the Avatar and convert it
//                                    AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(Base64.getDecoder().decode(sshGetPublicKeyAccept.pubKey()));
//                                    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricKeyParameter);
//
//                                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
//                                    java.security.PublicKey key = converter.getPublicKey(subjectPublicKeyInfo);
//                                    return key;
//                                }
//
//                                @Override
//                                public byte[] sign(byte[] key, byte[] data) {
//
//                                    // Read the request on wire, send it over to the Avatar and onward for signing
//                                    SshProtocolMessages.SshSignEventRequest request = new SshProtocolMessages.SshSignEventRequest(key, data);
//                                    SshProtocolMessages.SshSignEventAccept sshSignEventAccept = scas.service.signEvent(request);
//
//                                    return sshSignEventAccept.signature();
//                                }
//                            };
//
//                            // Very nicely hardcoded that we process no less than 3 requests from the ssh client
//                            try {
//                                while (true) {
//                                    connection.processNextToken();
//                                }
//                            } catch (ClientClosedException eof) {
//                                log.atInfo().log("Agent closed");
//                            }
//                        }
//                    });
//
//
//                    connectionThread.start();
//                }
//            }
//        });
//
//        agentThread.start();
    }
}
