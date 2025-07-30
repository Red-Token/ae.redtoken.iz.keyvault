package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import lombok.SneakyThrows;

public class MessageSender<A, R> {
    final AbstractLinkSender<R> sender;

    public MessageSender(AbstractLinkSender<R> sender) {
        this.sender = sender;
    }

    @SneakyThrows
    private byte[] pack(A message) {
        return LinkService.mapper.writeValueAsBytes(message);
    }

    @SneakyThrows
    public void sendMessage(A message) {
        sender.sendPacket(pack(message));
    }

    @SneakyThrows
    public void sendMessage(A message, R route) {
        sender.sendPacket(pack(message), route);
    }
}
