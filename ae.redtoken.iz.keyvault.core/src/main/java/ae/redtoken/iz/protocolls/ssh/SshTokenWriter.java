package ae.redtoken.iz.protocolls.ssh;

import jnr.unixsocket.UnixSocketChannel;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;

class SshTokenWriter {
    final UnixSocketChannel channel;

    public SshTokenWriter(UnixSocketChannel channel) {
        this.channel = channel;
    }

    public void writeSshToken(SshTokeReader.AbstractSshToken token) throws IOException {
        writeTokenBytes(token.toByteArray());
    }

    @SneakyThrows
    public void writeTokenBytes(byte[] bytes) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(bytes.length);
        dos.write(bytes);
        System.out.println("W:" + bytes.length + ":" + Base64.getEncoder().encodeToString(bytes));

        this.channel.write(ByteBuffer.wrap(baos.toByteArray()));
//
//
//
//            ByteBuffer buffer = ByteBuffer.wrap(new byte[4 + bytes.length]);
//            buffer.order(ByteOrder.BIG_ENDIAN);
//            buffer.putInt(bytes.length);
//            buffer.put(bytes);
//            this.channel.write(buffer);
        //           this.channel.write(ByteBuffer.wrap(bytes));

//            ByteBuffer buffer = ByteBuffer.wrap(new byte[4]);
//            buffer.order(ByteOrder.BIG_ENDIAN);
//            buffer.putInt(bytes.length);
//            this.channel.write(buffer);
//            this.channel.write(ByteBuffer.wrap(bytes));
    }
}
