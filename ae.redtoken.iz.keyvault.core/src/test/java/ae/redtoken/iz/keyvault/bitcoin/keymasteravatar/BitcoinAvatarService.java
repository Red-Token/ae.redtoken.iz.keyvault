package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfiguration;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.Preconditions;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.RedeemData;
import org.bitcoinj.wallet.Wallet;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class BitcoinAvatarService {

    public final Wallet wallet;
//    final private BitcoinMasterService masterService;
    IBitcoinConfiguration masterService;

    public BitcoinAvatarService(Network network, KeyChainGroup keyChainGroup, IBitcoinConfiguration masterService) {

        // Let's see what we can autodetect

        this.wallet = new Wallet(network, keyChainGroup) {
            public boolean canSignFor(Script script) {
                if (ScriptPattern.isP2PK(script)) {
                    byte[] pubkey = ScriptPattern.extractKeyFromP2PK(script);
                    ECKey key = this.findKeyFromPubKey(pubkey);
                    return key != null;
                } else if (ScriptPattern.isP2SH(script)) {
                    RedeemData data = this.findRedeemDataFromScriptHash(ScriptPattern.extractHashFromP2SH(script));
                    return data != null && this.canSignFor(data.redeemScript);
                } else if (ScriptPattern.isP2PKH(script)) {
                    ECKey key = this.findKeyFromPubKeyHash(ScriptPattern.extractHashFromP2PKH(script), ScriptType.P2PKH);
                    return key != null;
                } else if (ScriptPattern.isP2WPKH(script)) {
                    ECKey key = this.findKeyFromPubKeyHash(ScriptPattern.extractHashFromP2WH(script), ScriptType.P2WPKH);
                    return key != null && key.isCompressed();
                } else {
                    if (ScriptPattern.isSentToMultisig(script)) {
                        for (ECKey pubkey : script.getPubKeys()) {
                            ECKey key = this.findKeyFromPubKey(pubkey.getPubKey());
                            if (key != null) {
                                return true;
                            }
                        }
                    }

                    return false;
                }
            }
        };
//            super(network, keyChainGroup);
        this.masterService = masterService;
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


//        @Override
//        public void completeTx(SendRequest req) throws InsufficientMoneyException, TransactionCompletionException {
//            super.completeTx(req);
//        }


    public Transaction signTransaction(Transaction tx) {
        prepareTransaction(tx);

        Map<byte[], byte[]> map = new HashMap<>();
        tx.getInputs().forEach(ti -> map.put(ti.getOutpoint().hash().getBytes(),
                Objects.requireNonNull(Objects.requireNonNull(ti.getConnectedOutput()).getParentTransaction()).serialize()));

        // Create the request and send it over wire
        BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request = new BitcoinProtocolMessages.BitcoinTransactionSignatureRequest(tx.serialize(), map);

        // The master receives the request and signs it
        BitcoinProtocolMessages.BitcoinTransactionSignatureAccept accept = masterService.signTransaction(request);
        return Transaction.read(ByteBuffer.wrap(accept.tx()));
    }
}
