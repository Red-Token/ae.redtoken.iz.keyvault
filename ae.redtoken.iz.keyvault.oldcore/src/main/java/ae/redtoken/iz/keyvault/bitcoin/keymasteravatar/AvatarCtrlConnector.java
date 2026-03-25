package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IKeyMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.avatarctrl.IAvatarCtrlService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IIdentityService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.INostrConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh.ISshConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.AvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import lombok.SneakyThrows;
import nostr.id.Identity;
import org.bitcoinj.base.internal.Preconditions;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.wallet.*;

import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.*;

public class AvatarCtrlConnector extends AvatarConnector<KeyMasterStackedService> {

    Identity identity = Identity.generateRandomIdentity();

    public abstract static class AbstractNestedAvatarService<A extends IStackedService> {
        private final List<String> fullId;
        public final A service;

        public AbstractNestedAvatarService(List<String> fullId, A service) {
            this.fullId = fullId;
            this.service = service;
        }

        public String getId() {
            return fullId.getLast();
        }

        public List<String> subId(String id) {
            List<String> tmp = new ArrayList<>(fullId);
            tmp.add(id);
            return List.copyOf(tmp);
        }
    }

    public class AvatarCtrlService extends AbstractNestedAvatarService<IAvatarCtrlService> {
        public AvatarCtrlService() {
            this(List.of());
        }

        public AvatarCtrlService(List<String> fullId) {
            super(List.of(), createProxy(fullId, IAvatarCtrlService.class));
        }
    }

    @SneakyThrows
    public AvatarCtrlConnector(DatagramSocket socket, SocketAddress address) {
        super();

        socket.connect(address);
        RequestSender<NostrRoute> requestSender = new RequestSender<>(new NostrOverUdpSender(socket, identity));
        boolean running = true;

        this.sender = request -> {
            NostrRoute route = new NostrRoute();
            route.senderPubKey = null;
            requestSender.sendMessage(request, route);
        };

        Thread rt = new Thread(() -> {
            ResponseReceiver<NostrRoute> rr = new ResponseReceiver<>(new NostrOverUdpReceiver(socket));

            while (running) {
                onResponse(rr.receive());
            }
        });
        rt.start();
    }

    public AvatarCtrlConnector(KeyMasterExecutor keyMasterRunnable) {
        super(keyMasterRunnable);
    }
}
