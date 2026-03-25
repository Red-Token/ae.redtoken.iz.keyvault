package ae.redtoken.iz.protocolls.ssh;

import jnr.unixsocket.UnixServerSocketChannel;
import jnr.unixsocket.UnixSocketAddress;
import lombok.SneakyThrows;

import java.io.File;

public class SshAgent {
    public UnixServerSocketChannel server;

    @SneakyThrows
    public SshAgent() {
        String inSocketName = "/tmp/zool.sock";
        File inSocketFile = new File(inSocketName);
        inSocketFile.delete(); // make sure old socket is removed

        UnixSocketAddress inAddress = new UnixSocketAddress(inSocketFile);
        server = UnixServerSocketChannel.open();
        server.configureBlocking(true);
        server.socket().bind(inAddress);
    }
}
