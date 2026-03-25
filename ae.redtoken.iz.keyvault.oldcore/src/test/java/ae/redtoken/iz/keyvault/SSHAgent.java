package ae.redtoken.iz.keyvault;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.nio.ByteBuffer.*;

public class SSHAgent {
    private static final int SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private static final int SSH_AGENT_IDENTITIES_ANSWER = 12;
    private static final int SSH_AGENTC_SIGN_REQUEST = 13;
    private static final int SSH_AGENT_SIGN_RESPONSE = 14;

    private final Map<String, KeyPair> keys = new HashMap<>();

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SSHAgent agent = new SSHAgent();
        agent.start();
    }

    public void start() throws IOException {
        String socketPath = "/tmp/custom-ssh-agent.sock";
        File socketFile = new File(socketPath);
        if (socketFile.exists()) {
            socketFile.delete();
        }

        UnixDomainSocketAddress udsa = UnixDomainSocketAddress.of(socketPath);

        ServerSocketChannel serverChannel = ServerSocketChannel
                .open(StandardProtocolFamily.UNIX);

        serverChannel.bind(udsa);

        while (true) {
            SocketChannel channel = serverChannel.accept();
            DataInputStream in = new DataInputStream(Channels.newInputStream(channel));
            DataOutputStream out = new DataOutputStream(Channels.newOutputStream(channel));

            int messageType = in.readInt();
            switch (messageType) {
                case SSH_AGENTC_REQUEST_IDENTITIES:
                    handleRequestIdentities(out);
                    break;
                case SSH_AGENTC_SIGN_REQUEST:
                    handleSignRequest(in, out);
                    break;
                default:
                    System.out.println("Unsupported message type: " + messageType);
            }
        }
    }

    private void handleRequestIdentities(DataOutputStream out) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(buffer);

        // Number of keys
        data.writeInt(keys.size());

        for (Map.Entry<String, KeyPair> entry : keys.entrySet()) {
            RSAPublicKey publicKey = (RSAPublicKey) entry.getValue().getPublic();

            // Write public key blob
            ByteArrayOutputStream keyBlob = new ByteArrayOutputStream();
            DataOutputStream keyData = new DataOutputStream(keyBlob);
            keyData.writeUTF("ssh-rsa");
            keyData.write(publicKey.getPublicExponent().toByteArray());
            keyData.write(publicKey.getModulus().toByteArray());

            data.writeInt(keyBlob.size());
            data.write(keyBlob.toByteArray());

            // Write key comment
            data.writeUTF(entry.getKey());
        }

        // Write response
        out.writeByte(SSH_AGENT_IDENTITIES_ANSWER);
        out.writeInt(buffer.size());
        out.write(buffer.toByteArray());
    }

    private void handleSignRequest(DataInputStream in, DataOutputStream out) throws IOException {
        // Read key blob
        int blobLength = in.readInt();
        byte[] blob = new byte[blobLength];
        in.readFully(blob);

        // Read data to sign
        int dataLength = in.readInt();
        byte[] data = new byte[dataLength];
        in.readFully(data);

        // Find the key
        String keyComment = new String(blob);
        KeyPair keyPair = keys.get(keyComment);
        if (keyPair == null) {
            System.out.println("Key not found: " + keyComment);
            return;
        }

        // Sign the data
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            byte[] signedData = signature.sign();

            // Write response
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream bufferData = new DataOutputStream(buffer);
            bufferData.writeUTF("ssh-rsa");
            bufferData.writeInt(signedData.length);
            bufferData.write(signedData);

            out.writeByte(SSH_AGENT_SIGN_RESPONSE);
            out.writeInt(buffer.size());
            out.write(buffer.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addKey(String comment, KeyPair keyPair) {
        keys.put(comment, keyPair);
    }
}