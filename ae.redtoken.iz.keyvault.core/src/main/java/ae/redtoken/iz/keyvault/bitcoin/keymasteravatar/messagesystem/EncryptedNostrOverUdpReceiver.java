package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.AvatarSpawnPoint;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nostr.api.NIP44;
import nostr.event.impl.GenericEvent;
import nostr.id.Identity;

import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;

@Slf4j
public class EncryptedNostrOverUdpReceiver extends NostrOverUdpReceiver {

    public EncryptedNostrOverUdpReceiver(DatagramSocket socket, Identity recipient) {
        super(socket, recipient);
    }

    @SneakyThrows
    public byte[] receivePacket(RouteInfo<NostrRoute> routeInfo) {
        GenericEvent event = receiveEvent(routeInfo);
        return NIP44.decrypt(recipient, event.getContent(), event.getPubKey()).getBytes(StandardCharsets.UTF_8);
    }
}
