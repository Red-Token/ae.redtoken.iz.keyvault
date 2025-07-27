package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IKeyMasterService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IIdentityService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.Avatar;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
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

import java.nio.ByteBuffer;
import java.util.*;

public class KeyMasterAvatar extends Avatar<KeyMasterStackedService> {

    public static BitcoinAvatarService fromWatchingKey(Network network, DeterministicKey watchKey, Collection<ScriptType> outputScriptTypes, IBitcoinConfigurationService masterService) {
        List<DeterministicKeyChain> chains = outputScriptTypes.stream()
                .map(type ->
                        DeterministicKeyChain.builder()
                                .watch(watchKey)
                                .outputScriptType(type)
                                .build())
                .toList();
        return new BitcoinAvatarService(network, KeyChainGroup.builder(network).chains(chains).build(), masterService);
    }

    static class NestedAvatarService<A extends IStackedService> {
        private final List<String> fullId;
        public final A service;

        public NestedAvatarService(List<String> fullId, A service) {
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

    public class KeyMasterAvatarService extends NestedAvatarService<IKeyMasterService> {
        public KeyMasterAvatarService() {
            this(List.of());
        }

        public KeyMasterAvatarService(List<String> fullId) {
            super(List.of(), createProxy(fullId, IKeyMasterService.class));
        }
    }

    public class IdentityAvatarService extends NestedAvatarService<IIdentityService> {
        public IdentityAvatarService(List<String> id) {
            super(id, createProxy(id.toArray(new String[0]), IIdentityService.class));
        }
    }

    public class BitcoinProtocolAvatarService extends NestedAvatarService<IStackedService> {

        public BitcoinProtocolAvatarService(List<String> fullId) {
            super(fullId, createProxy(fullId, IStackedService.class));
        }
    }

    public class BitcoinConfigurationAvatarService extends NestedAvatarService<IBitcoinConfigurationService> {
        public final BitcoinAvatarService bitcoinAvatarService;
        public final Wallet wallet;

        public BitcoinConfigurationAvatarService(List<String> fullId) {
            this(fullId, createProxy(fullId, IBitcoinConfigurationService.class));
        }

        public BitcoinConfigurationAvatarService(List<String> fullId, IBitcoinConfigurationService bitcoinConfigurationService) {
            super(fullId, bitcoinConfigurationService);
            this.bitcoinAvatarService = createBitcoinAvatarService(bitcoinConfigurationService);
            this.wallet = bitcoinAvatarService.wallet;
        }

        static public BitcoinAvatarService createBitcoinAvatarService(IBitcoinConfigurationService bitcoinConfigurationService) {
            BitcoinProtocolMessages.GetWatchingKeyAccept wk = bitcoinConfigurationService.getWatchingKey();

            DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey(), wk.network());
            return fromWatchingKey(wk.network(), watchingKey, wk.scriptTypes(), bitcoinConfigurationService);
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

    final KeyMasterStackedService keyMaster;
    public final IKeyMasterService service;

    public KeyMasterAvatar(KeyMasterRunnable keyMasterRunnable) {
        this.masterRunnable = keyMasterRunnable;
        this.keyMaster = masterRunnable.rootStackedService;
        this.service = createProxy(new String[0], IKeyMasterService.class);
    }

//    public IdentityAvatar getDefaultIdentity() {
//
//        return new IdentityAvatar((IdentityStackedService) keyMaster.subServices.get(keyMaster.getDefaultId()));
////        return keyMaster.getDefaultId();
//    }

//    Collection<IdentityStackedService> getIdentities() {
//        return keyMaster.getIdentities();
//    }
//
//    public IdentityStackedService getDefaultIdentity() {
//        return keyMaster.getDefaultIdentity();
//    }

}
