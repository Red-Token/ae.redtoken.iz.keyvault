package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

public abstract class AbstractLinkSender<R> {
    public void sendPacket(byte[] packet) {
        sendPacket(packet, null);
    }

    public abstract void sendPacket(byte[] packet, R route);
}
