package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.RedeemData;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.stream.Collectors;

public class BitcoinMasterService {
    private final KeyVaultProxy.BitcoinProtocolExecutor executor;
    private final KeyChainGroup wkcg;

    class WrapedKeyBag implements KeyBag {
        @Nullable
        @Override
        public ECKey findKeyFromPubKeyHash(byte[] bytes, @Nullable ScriptType scriptType) {
            ECKey keyFromPubKeyHash = wkcg.findKeyFromPubKeyHash(bytes, scriptType);

            if (keyFromPubKeyHash == null) {
                return null;
            }

            return executor.new WrapedEcKey(keyFromPubKeyHash.getPubKeyPoint(), keyFromPubKeyHash.isCompressed(), scriptType);
        }

        @Nullable
        @Override
        public ECKey findKeyFromPubKey(byte[] bytes) {
            return wkcg.findKeyFromPubKey(bytes);
        }

        @Nullable
        @Override
        public RedeemData findRedeemDataFromScriptHash(byte[] bytes) {
            return wkcg.findRedeemDataFromScriptHash(bytes);
        }
    }

//    public BitcoinMasterService(KeyVaultProxy proxy, BitcoinConfiguration config) {
//        // TODO: The proxy should be in the parent
//        this(proxy.new BitcoinProtocolExecutor(config), config);
//    }

    public BitcoinMasterService(KeyVaultProxy.BitcoinProtocolExecutor executor, BitcoinConfiguration config) {
        this.executor = executor;

        KeyChainGroup.Builder kcgb = KeyChainGroup.builder(config.network());
        DeterministicKey watchKey = DeterministicKey.deserializeB58(executor.getWatchingKey(), config.network());

        for (ScriptType outputScriptType : config.scriptTypes()) {
            DeterministicKeyChain chain = DeterministicKeyChain.builder().watch(watchKey).outputScriptType(outputScriptType).build();
            chain.setLookaheadSize(100);
            chain.maybeLookAhead();
            kcgb.addChain(chain);
        }

        this.wkcg = kcgb.build();
    }

    public BitcoinProtocolM.GetWatchingKeyAccept getWatchingKey() {
        return new BitcoinProtocolM.GetWatchingKeyAccept(
                executor.getWatchingKey(),
                executor.config.scriptTypes(),
                executor.config.network());
    }

    public BitcoinProtocolM.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolM.BitcoinTransactionSignatureRequest request) {
        Transaction transaction = Transaction.read(ByteBuffer.wrap(request.tx()));

        // Convert the binary map into Objects
        Map<Sha256Hash, Transaction> transactionMap = request.map().entrySet().stream().collect(Collectors.toUnmodifiableMap(
                entry -> Sha256Hash.wrap(entry.getKey()),
                entry -> Transaction.read(ByteBuffer.wrap(entry.getValue()))));

        // Connect the inputs in the request to the outputs
        transaction.getInputs().forEach(ti -> {
            ti.connect(transactionMap.get(ti.getOutpoint().hash()).getOutput(ti.getOutpoint().index()));
        });

        // Prompts the user

        //Yey, we are
        TransactionSigner.ProposedTransaction pt = new TransactionSigner.ProposedTransaction(transaction);
        LocalTransactionSigner signer = new LocalTransactionSigner();
        signer.signInputs(pt, new WrapedKeyBag());
        return new BitcoinProtocolM.BitcoinTransactionSignatureAccept(transaction.serialize());
    }
}
