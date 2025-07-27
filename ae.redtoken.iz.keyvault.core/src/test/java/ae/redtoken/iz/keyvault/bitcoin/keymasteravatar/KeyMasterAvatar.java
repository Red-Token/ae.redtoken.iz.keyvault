package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IKeyMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IIdentityService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Avatar;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.MasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Request;
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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.*;

public class KeyMasterAvatar extends Avatar<KeyMasterStackedService> {

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

    public KeyMasterAvatar(DatagramSocket socket, SocketAddress address) {
        super();

        sender = new DirectRequestSender<>(null) {
            @SneakyThrows
            @Override
            public void sendRequest(Request request) {
                byte[] data = mapper.writeValueAsBytes(request);
                DatagramPacket packet = new DatagramPacket(data, data.length, address);
                socket.send(packet);
            }
        };

        receiver = new DirectResponseReceiver<>(this);

        boolean running = true;

        Thread rt = new Thread(() -> {
            while (running) {
                try {
                    byte[] buffer = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);
                    receiver.receiveResponse(Arrays.copyOfRange(packet.getData(), 0, packet.getLength()));

                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        rt.start();


    }


    public KeyMasterAvatar(KeyMasterRunnable keyMasterRunnable) {
        super(keyMasterRunnable);
    }
}
