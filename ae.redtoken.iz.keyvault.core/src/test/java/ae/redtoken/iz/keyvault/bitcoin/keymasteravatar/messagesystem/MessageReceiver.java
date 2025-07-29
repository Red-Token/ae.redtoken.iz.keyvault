package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import lombok.SneakyThrows;

class MessageReceiver<A, R> {
    final AbstractLinkReceiver<R> receiver;
    final Class<A> cls;

    MessageReceiver(AbstractLinkReceiver<R> receiver, Class<A> cls) {
        this.receiver = receiver;
        this.cls = cls;
    }

    public A receive() {
        return receive(null);
    }

    @SneakyThrows
    public A receive(AbstractLinkReceiver.RouteInfo<R> info) {
        return LinkService.mapper.readValue(receiver.receivePacket(info), cls);
    }
}
