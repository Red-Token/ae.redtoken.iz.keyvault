package ae.redtoken.iz.protocolls.ssh;

import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;

class SshTokeReader {
    final UnixSocketChannel channel;

    SshTokeReader(UnixSocketChannel channel) {
        this.channel = channel;


    }

    @SneakyThrows
    private int readUint32() {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int x = this.channel.read(buffer);

        if (x == -1)
            throw new ClientClosedException();

        if (x != 4)
            throw new RuntimeException("Wrong number of bytes read " + x);

        buffer.rewind();
        return buffer.getInt();
    }

    @SneakyThrows
    AbstractSshToken readSshToken() {
        byte[] bytes = readTokenBytes();

        ByteBuffer requestBuffer = ByteBuffer.wrap(bytes);
        SshTokenType requestType = SshTokeReader.tokenMap.get(requestBuffer.get());

        System.out.println(bytes.length);
        System.out.println(requestType);

        return SshTokeReader.tokenMapConstructor.get(requestType).newInstance(requestBuffer);
    }

    @SneakyThrows
    byte[] readTokenBytes() {
        int length = readUint32();
        ByteBuffer buffer = ByteBuffer.allocate(length);

        if (this.channel.read(buffer) != length)
            throw new RuntimeException("Wrong number of bytes read");

        buffer.rewind();
        byte[] bytes = buffer.array();

        System.out.println("R:" + bytes.length + ":" + Base64.getEncoder().encodeToString(bytes));
        return bytes;
    }

    final static Map<Byte, SshTokenType> tokenMap = new HashMap<>();
    final static Map<SshTokenType, Constructor<? extends AbstractSshToken>> tokenMapConstructor = new HashMap<>();

    static {
        for (SshTokenType token : SshTokenType.values()) {
            tokenMap.put(token.code, token);

            try {
                tokenMapConstructor.put(SshTokenType.SSH_AGENT_IDENTITIES_ANSWER, SshAgentIdentitiesAnswer.class.getConstructor(ByteBuffer.class));
                tokenMapConstructor.put(SshTokenType.SSH_AGENTC_REQUEST_IDENTITIES, SshAgentCRequestIdentities.class.getConstructor(ByteBuffer.class));
                tokenMapConstructor.put(SshTokenType.SSH_AGENTC_EXTENSION, SshAgentCExetion.class.getConstructor(ByteBuffer.class));
                tokenMapConstructor.put(SshTokenType.SSH_AGENT_FAILURE, SshAgentFailure.class.getConstructor(ByteBuffer.class));
                tokenMapConstructor.put(SshTokenType.SSH_AGENTC_SIGN_REQUEST, SshAgentCSignRequest.class.getConstructor(ByteBuffer.class));
                tokenMapConstructor.put(SshTokenType.SSH_AGENT_SIGN_RESPONSE, SshAgentSignResponse.class.getConstructor(ByteBuffer.class));

            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            }

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
        final SshTokenType type;

        static byte[] readByteArray(ByteBuffer buffer) {
            int stringSize = buffer.getInt();
            byte[] bytes = new byte[stringSize];
            buffer.get(bytes);
            return bytes;
        }

        static String readString(ByteBuffer buffer) {
            return new String(readByteArray(buffer));
        }

        @SneakyThrows
        static PublicKey readPublicKey(ByteBuffer buffer) {
            byte[] keyBytes = readByteArray(buffer);
            ByteArrayBuffer bab = new ByteArrayBuffer(keyBytes);
            return bab.getRawPublicKey();
        }

        static long readUint32(ByteBuffer buffer) {
            return buffer.getInt();
        }

        static void writePublicKey(DataOutputStream dos, PublicKey publicKey) {
            ByteArrayBuffer bab = new ByteArrayBuffer();
            bab.putPublicKey(publicKey);
            writeByteArray(dos, bab.getBytes());
        }

        static void writeString(DataOutputStream dos, String string) {
            writeByteArray(dos, string.getBytes(StandardCharsets.UTF_8));
        }

        @SneakyThrows
        static void writeByteArray(DataOutputStream dos, byte[] bytes) {
            dos.writeInt(bytes.length);
            dos.write(bytes);
        }


        public AbstractSshToken(SshTokenType type) {
            this.type = type;
        }

        public byte[] toByteArray() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(type.code);
            populate(out);
            return out.toByteArray();
        }

        protected void populate(ByteArrayOutputStream out) {
        }

        @SneakyThrows
        protected void writeUint32(DataOutputStream dos, long flags) {
            dos.writeInt((int) flags);
        }
    }

    static class SshAgentCRequestIdentities extends AbstractSshToken {
        public SshAgentCRequestIdentities() {
            super(SshTokenType.SSH_AGENTC_REQUEST_IDENTITIES);
        }

        public SshAgentCRequestIdentities(ByteBuffer buffer) {
            this();
        }
    }

    static class SshAgentCExetion extends AbstractSshToken {

        record Extention(byte[] hostkey, byte[] sessionIdentifier, byte[] signature, boolean isForwarding) {
        }

        public SshAgentCExetion() {
            super(SshTokenType.SSH_AGENTC_EXTENSION);
        }

        String zoola;
        SshAgentCExetion.Extention extention;

        public SshAgentCExetion(ByteBuffer buffer) {
            this();

            this.zoola = readString(buffer);
            this.extention = new SshAgentCExetion.Extention(
                    readByteArray(buffer),
                    readByteArray(buffer),
                    readByteArray(buffer),
                    buffer.get() != 0);

            int remaining = buffer.remaining();
            System.out.println(remaining);
        }

        @SneakyThrows
        @Override
        protected void populate(ByteArrayOutputStream out) {
            DataOutputStream dataOutputStream = new DataOutputStream(out);
            dataOutputStream.writeInt(this.zoola.length());
            dataOutputStream.write(zoola.getBytes(StandardCharsets.UTF_8));
            dataOutputStream.writeInt(extention.hostkey.length);
            dataOutputStream.write(extention.hostkey);
            dataOutputStream.writeInt(extention.sessionIdentifier.length);
            dataOutputStream.write(extention.sessionIdentifier);
            dataOutputStream.writeInt(extention.sessionIdentifier.length);
            dataOutputStream.write(extention.signature);
            dataOutputStream.writeByte(extention.isForwarding ? 1 : 0);
        }
    }

    static class SshAgentFailure extends AbstractSshToken {
        public SshAgentFailure() {
            super(SshTokenType.SSH_AGENT_FAILURE);
        }

        public SshAgentFailure(ByteBuffer buffer) {
            super(SshTokenType.SSH_AGENT_FAILURE);
        }
    }

    static class SshAgentCSignRequest extends AbstractSshToken {

        PublicKey key;
        byte[] data;
        long flags;

        public SshAgentCSignRequest(ByteBuffer buffer) {
            super(SshTokenType.SSH_AGENTC_SIGN_REQUEST);

            key = readPublicKey(buffer);
            data = readByteArray(buffer);
            flags = readUint32(buffer);
        }

        @SneakyThrows
        protected void populate(ByteArrayOutputStream out) {
            DataOutputStream dos = new DataOutputStream(out);

            writePublicKey(dos, key);
            writeByteArray(dos, data);
            writeUint32(dos, flags);
        }
    }

    static class SshAgentSignResponse extends AbstractSshToken {
        record SshSignature(String type, byte[] signature) {
        }

        //            final byte[] signature;
        final SshAgentSignResponse.SshSignature signature;

        public SshAgentSignResponse(SshAgentSignResponse.SshSignature signature) {
            super(SshTokenType.SSH_AGENT_SIGN_RESPONSE);
            this.signature = signature;
        }

        public SshAgentSignResponse(byte[] data) {
            super(SshTokenType.SSH_AGENT_SIGN_RESPONSE);
            ByteBuffer buf = ByteBuffer.wrap(data);
            this.signature = new SshAgentSignResponse.SshSignature(readString(buf), readByteArray(buf));
        }

        public SshAgentSignResponse(ByteBuffer buffer) {
            this(readByteArray(buffer));
        }

        @SneakyThrows
        protected void populate(ByteArrayOutputStream out) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(buffer);
            writeString(dataOutputStream, signature.type);
            writeByteArray(dataOutputStream, signature.signature);

            DataOutputStream dos = new DataOutputStream(out);
            writeByteArray(dos, buffer.toByteArray());
        }
    }


    static class SshAgentIdentitiesAnswer extends AbstractSshToken {
        record Key(PublicKey key, String comment) {
        }

        Collection<SshAgentIdentitiesAnswer.Key> keys = new ArrayList<>();

        public SshAgentIdentitiesAnswer() {
            super(SshTokenType.SSH_AGENT_IDENTITIES_ANSWER);
        }

        @SneakyThrows
        public SshAgentIdentitiesAnswer(ByteBuffer buffer) {
            super(SshTokenType.SSH_AGENT_IDENTITIES_ANSWER);

            long size = readUint32(buffer);

            for (int i = 0; i < size; i++) {
                byte[] keyBytes = readByteArray(buffer);
                ByteArrayBuffer bab = new ByteArrayBuffer(keyBytes);
                PublicKey publicKey = bab.getRawPublicKey();

                String comment = readString(buffer);
                keys.add(new SshAgentIdentitiesAnswer.Key(publicKey, comment));
            }
        }

        @SneakyThrows
        @Override
        protected void populate(ByteArrayOutputStream out) {
            super.populate(out);
            DataOutputStream dataOutputStream = new DataOutputStream(out);
            dataOutputStream.writeInt(keys.size());

            for (SshAgentIdentitiesAnswer.Key key : keys) {
                writePublicKey(dataOutputStream, key.key);
                writeString(dataOutputStream, key.comment);
            }
        }
    }
}
