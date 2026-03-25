package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

public abstract class AbstractLinkReceiver<R> {
    static public class RouteInfo<R> {
        public R route;
    }

    final public byte[] receivePacket() {
        return receivePacket(null);
    }

    public abstract byte[] receivePacket(RouteInfo<R> routeInfo);
}
