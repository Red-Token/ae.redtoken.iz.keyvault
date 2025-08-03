package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IKeyMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IIdentityService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.INostrConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.*;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.AvatarConnector;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import lombok.SneakyThrows;
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

public class KeyMasterAvatarConnector extends AvatarConnector<KeyMasterStackedService> {

    abstract static class AbstractNestedAvatarService<A extends IStackedService> {
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

    public class KeyMasterAvatarService extends AbstractNestedAvatarService<IKeyMasterService> {
        public KeyMasterAvatarService() {
            this(List.of());
        }

        public KeyMasterAvatarService(List<String> fullId) {
            super(List.of(), createProxy(fullId, IKeyMasterService.class));
        }
    }

    public class IdentityAvatarService extends AbstractNestedAvatarService<IIdentityService> {
        public IdentityAvatarService(List<String> id) {
            super(id, createProxy(id.toArray(new String[0]), IIdentityService.class));
        }
    }

    public class NostrProtocolAvatarService extends AbstractNestedAvatarService<IStackedService> {

        public NostrProtocolAvatarService(List<String> fullId) {
            super(fullId, createProxy(fullId, IStackedService.class));
        }
    }

    public class NostrConfigurationAvatarService extends AbstractNestedAvatarService<INostrConfigurationService> {

        public NostrConfigurationAvatarService(List<String> fullId) {
            this(fullId, createProxy(fullId, INostrConfigurationService.class));
        }

        public NostrConfigurationAvatarService(List<String> fullId, INostrConfigurationService service) {
            super(fullId, service);
        }
    }

    public class BitcoinProtocolAvatarService extends AbstractNestedAvatarService<IStackedService> {

        public BitcoinProtocolAvatarService(List<String> fullId) {
            super(fullId, createProxy(fullId, IStackedService.class));
        }
    }

    public class BitcoinConfigurationAvatarService extends AbstractNestedAvatarService<IBitcoinConfigurationService> {
        public final Wallet wallet;

        public BitcoinConfigurationAvatarService(List<String> fullId) {
            this(fullId, createProxy(fullId, IBitcoinConfigurationService.class));
        }

        public BitcoinConfigurationAvatarService(List<String> fullId, IBitcoinConfigurationService bitcoinConfigurationService) {
            super(fullId, bitcoinConfigurationService);

            BitcoinProtocolMessages.GetWatchingKeyAccept gwka = this.service.getWatchingKey();
            DeterministicKey watchingKey = DeterministicKey.deserializeB58(gwka.watchingKey(), gwka.network());
            List<DeterministicKeyChain> chains = gwka.scriptTypes().stream()
                    .map(type ->
                            DeterministicKeyChain.builder()
                                    .watch(watchingKey)
                                    .outputScriptType(type)
                                    .build())
                    .toList();
            KeyChainGroup keyChainGroup = KeyChainGroup.builder(gwka.network()).chains(chains).build();
            this.wallet = new RemoteWallet(gwka.network(), keyChainGroup);
        }

        public void prepareTransaction(Transaction tx) throws Wallet.BadWalletEncryptionKeyException {
            try {
                List<TransactionInput> inputs = tx.getInputs();
                List<TransactionOutput> outputs = tx.getOutputs();
                Preconditions.checkState(inputs.size() > 0);
                Preconditions.checkState(outputs.size() > 0);

//                KeyBag maybeDecryptingKeyBag = new DecryptingKeyBag(internalWallet, req.aesKey);
                KeyBag maybeDecryptingKeyBag = this.wallet;

                int numInputs = tx.getInputs().size();

                for (int i = 0; i < numInputs; ++i) {
                    TransactionInput txIn = tx.getInput((long) i);
                    TransactionOutput connectedOutput = txIn.getConnectedOutput();
                    if (connectedOutput != null) {
                        Script scriptPubKey = connectedOutput.getScriptPubKey();

                        try {
                            txIn.getScriptSig().correctlySpends(tx, i, txIn.getWitness(), connectedOutput.getValue(), connectedOutput.getScriptPubKey(), Script.ALL_VERIFY_FLAGS);
                        } catch (ScriptException e) {
                            RedeemData redeemData = txIn.getConnectedRedeemData(maybeDecryptingKeyBag);
                            Objects.requireNonNull(redeemData, () -> "Transaction exists in wallet that we cannot redeem: " + txIn.getOutpoint().hash());
                            tx.replaceInput(i, txIn.withScriptSig(scriptPubKey.createEmptyInputScript((ECKey) redeemData.keys.get(0), redeemData.redeemScript)));
                        }
                    }
                }
            } catch (KeyCrypterException.PublicPrivateMismatch | KeyCrypterException.InvalidCipherText e) {
                throw new Wallet.BadWalletEncryptionKeyException(e);
            } finally {
            }
        }

        public Transaction signTransaction(Transaction tx) {
            prepareTransaction(tx);

            Map<byte[], byte[]> map = new HashMap<>();
            tx.getInputs().forEach(ti -> map.put(ti.getOutpoint().hash().getBytes(),
                    Objects.requireNonNull(Objects.requireNonNull(ti.getConnectedOutput()).getParentTransaction()).serialize()));

            // Create the request and send it over wire
            BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request = new BitcoinProtocolMessages.BitcoinTransactionSignatureRequest(tx.serialize(), map);

            // The master receives the request and signs it
            BitcoinProtocolMessages.BitcoinTransactionSignatureAccept accept = service.signTransaction(request);
            return Transaction.read(ByteBuffer.wrap(accept.tx()));
        }
    }

    @SneakyThrows
    public KeyMasterAvatarConnector(DatagramSocket socket, SocketAddress address) {
        super();

        socket.connect(address);
        RequestSender<SocketAddress> requestSender = new RequestSender<>(new UdpLinkSender(socket));
        boolean running = true;

        this.sender = requestSender::sendMessage;

        Thread rt = new Thread(() -> {
            ResponseReceiver<SocketAddress> rr = new ResponseReceiver<>(new UdpLinkReceiver(socket));

            while (running) {
                onResponse(rr.receive());
            }
        });
        rt.start();
    }


    public KeyMasterAvatarConnector(KeyMasterExecutor keyMasterRunnable) {
        super(keyMasterRunnable);
    }
}
