package ae.redtoken.iz.keyvault.bitcoin.ssh;

import jnr.unixsocket.UnixServerSocketChannel;
import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class TestSSH {

    public static void writeUint32(ByteArrayOutputStream out, long value) throws IOException {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Value out of range for uint32: " + value);
        }

        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    static class SshTokeReader {
        final UnixSocketChannel channel;

        SshTokeReader(UnixSocketChannel channel) {
            this.channel = channel;
        }

        @SneakyThrows
        private int readUint32() {
            ByteBuffer buffer = ByteBuffer.allocate(4);
            buffer.order(ByteOrder.BIG_ENDIAN);

            if (this.channel.read(buffer) != 4)
                throw new RuntimeException("Wrong number of bytes read");

            buffer.rewind();
            return buffer.getInt();
        }

        @SneakyThrows
        byte[] readToken() {
            int length = readUint32();
            ByteBuffer buffer = ByteBuffer.allocate(length);

            if (this.channel.read(buffer) != length)
                throw new RuntimeException("Wrong number of bytes read");

            buffer.rewind();
            return buffer.array();
        }

        final static Map<Byte, SshTokenType> tokenMap = new HashMap<>();

        static {
            for (SshTokenType token : SshTokenType.values()) {
                tokenMap.put(token.code, token);
            }
        }

        enum SshTokenType {
            SSH_AGENTC_REQUEST_IDENTITIES(11),
            SSH_AGENTC_SIGN_REQUEST(13),
            SSH_AGENTC_ADD_IDENTITY(17),
            SSH_AGENTC_REMOVE_IDENTITY(18),
            SSH_AGENTC_REMOVE_ALL_IDENTITIES(19),
            SSH_AGENTC_ADD_SMARTCARD_KEY(20),
            SSH_AGENTC_REMOVE_SMARTCARD_KEY(21),
            SSH_AGENTC_LOCK(22),
            SSH_AGENTC_UNLOCK(23),
            SSH_AGENTC_ADD_ID_CONSTRAINED(25),
            SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED(26),
            SSH_AGENTC_EXTENSION(27),
            SSH_AGENT_FAILURE(5),
            SSH_AGENT_SUCCESS(6),
            SSH_AGENT_IDENTITIES_ANSWER(12),
            SSH_AGENT_SIGN_RESPONSE(14),
            SSH_AGENT_EXTENSION_FAILURE(28),
            SSH_AGENT_EXTENSION_RESPONSE(29);

            final byte code;

            SshTokenType(int code) {
                this.code = (byte) code;
            }
        }

        abstract static class AbstractSshToken {

            public AbstractSshToken() {
            }
        }

        static class SshAgentCRequestIdentities extends AbstractSshToken {
            public SshAgentCRequestIdentities() {
            }
        }

        static class SshAgentIdentitiesAnswer extends AbstractSshToken {

            static String readString(ByteBuffer buffer) {
                int stringSize = buffer.getInt();
                byte[] bytes = new byte[stringSize];
                buffer.get(bytes);
                return new String(bytes);
            }

            static long readUint32(ByteBuffer buffer) {
                return buffer.getInt();
            }

            record Key(String key, String comment) {
            }

            Collection<Key> keys = new ArrayList<>();

            public SshAgentIdentitiesAnswer(ByteBuffer buffer) {
                long size = readUint32(buffer);

                for (int i = 0; i < size; i++) {
                    keys.add(new Key(readString(buffer), readString(buffer)));
                }
            }
        }
    }

    static class SshTokenWriter extends SshTokeReader.AbstractSshToken {
        final UnixSocketChannel channel;

        public SshTokenWriter(UnixSocketChannel channel) {
            this.channel = channel;
        }

        @SneakyThrows
        public void writeToken(byte[] bytes) {
            ByteBuffer buffer = ByteBuffer.wrap(new byte[4]);
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(bytes.length);
            this.channel.write(buffer);
            this.channel.write(ByteBuffer.wrap(bytes));
        }
    }


    @SneakyThrows
    @Test
    void testSshAgent() {
//        String sockName = "/tmp/ssh-Jo5obhsWd3xP/agent.479552";
        String outSocketName = "/run/user/1000/keyring/ssh";
//        String inSocketName = "/tmp/mysocket.sock";
//        File inSocketFile = new File(inSocketName);

//        inSocketFile.delete(); // make sure old socket is removed
//        UnixServerSocketChannel server = UnixServerSocketChannel.open();
//        server.configureBlocking(true);
//        server.socket().bind(new UnixSocketAddress(inSocketFile));
//
//        System.out.println("Waiting for connection...");
//        UnixSocketChannel inChannel = server.accept();

        File outSocketFile = new File(outSocketName);
        UnixSocketAddress address = new UnixSocketAddress(outSocketFile);
        UnixSocketChannel outChannel = UnixSocketChannel.open(address);

//        Thread t = new Thread(new Runnable() {
//            @SneakyThrows
//            @Override
//            public void run() {
//                // Connect to the server socket
//                SshTokeReader sshTokeReader = new SshTokeReader(inChannel);
//                SshTokenWriter sshTokenWriter = new SshTokenWriter(outChannel);
//
//                boolean running = true;
//                while (running) {
//                    byte[] bytes = sshTokeReader.readToken();
//
//                    System.out.println("Read " + bytes.length + " bytes");
//
//                    sshTokenWriter.writeToken(bytes);
//
//                    System.out.println("Writing " + bytes.length + " bytes");
//                }
//            }
//        });
//
//        Thread t2 = new Thread(new Runnable() {
//            @SneakyThrows
//            @Override
//            public void run() {
//                // Connect to the server socket
//                SshTokeReader sshTokeReader = new SshTokeReader(outChannel);
//                SshTokenWriter sshTokenWriter = new SshTokenWriter(inChannel);
//
//                boolean running = true;
//                while (running) {
//                    byte[] bytes = sshTokeReader.readToken();
//
//                    System.out.println("Read2 " + bytes.length + " bytes");
//
//                    sshTokenWriter.writeToken(bytes);
//
//                    System.out.println("Writing2 " + bytes.length + " bytes");
//                }
//            }
//        });
//
//        t2.start();
//        t.start();
//
//        t.join();
//
//
        // Let there be light at the end of the tunnel
        File socketFile = new File(outSocketName);

        // Connect to the server socket
//        UnixSocketAddress address = new UnixSocketAddress(outSocketFile);
        UnixSocketChannel channel = UnixSocketChannel.open(address);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(stream);

        byte[] bytes = new byte[]{11};

        ByteBuffer buffer = ByteBuffer.wrap(new byte[4]);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(bytes.length);


//        writeUint32(stream, 1);
//        dos.write(11);

        // Send a message
//        ByteBuffer buffer = ByteBuffer.wrap(stream.toByteArray());
        channel.write(buffer);
        channel.write(ByteBuffer.wrap(bytes));
//        channel.close();

        SshTokeReader sshTokeReader = new SshTokeReader(channel);

        byte[] bytes2 = sshTokeReader.readToken();

        ByteBuffer buffer2 = ByteBuffer.wrap(bytes2);
        SshTokeReader.SshTokenType type = SshTokeReader.tokenMap.get(buffer2.get());

        Map<SshTokeReader.SshTokenType, Constructor<?>> tokenMapConstructor = new HashMap<>();
        tokenMapConstructor.put(SshTokeReader.SshTokenType.SSH_AGENT_IDENTITIES_ANSWER, SshTokeReader.SshAgentIdentitiesAnswer.class.getConstructor(ByteBuffer.class));

        SshTokeReader.SshAgentIdentitiesAnswer sshAgentIdentitiesAnswer = new SshTokeReader.SshAgentIdentitiesAnswer(buffer2);

//        ByteBuffer buffery2 = ByteBuffer.wrap(new byte[100]);
//
//        ByteBuffer buffer2 = ByteBuffer.wrap(new byte[100]);
//
//        channel.read(buffer2);

        System.out.println("sdfsfsfsdfsdf");
    }

    @SneakyThrows
    @Test
    void testAgent() {

        Thread t = new Thread(new Runnable() {

            @SneakyThrows
            @Override
            public void run() {
                File socketFile = new File("/tmp/mysocket.sock");
                socketFile.delete(); // make sure old socket is removed

                UnixServerSocketChannel server = UnixServerSocketChannel.open();
                try {
                    server.configureBlocking(true);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                server.socket().bind(new UnixSocketAddress(socketFile));

                System.out.println("Waiting for connection...");
                UnixSocketChannel client = server.accept();
                ByteBuffer buffer = ByteBuffer.allocate(1024);
                client.read(buffer);

                System.out.println("Received: " + new String(buffer.array()).trim());
                client.close();
                server.close();
            }
        });

        t.start();

        Thread.sleep(1000);

        // Let there be light at the end of the tunnel
        File socketFile = new File("/tmp/mysocket.sock");

        // Connect to the server socket
        UnixSocketAddress address = new UnixSocketAddress(socketFile);
        UnixSocketChannel channel = UnixSocketChannel.open(address);

        // Send a message
        ByteBuffer buffer = ByteBuffer.wrap("Hello server".getBytes());
        channel.write(buffer);
        channel.close();
    }
}
