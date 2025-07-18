package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.*;
import org.bitcoinj.base.internal.Preconditions;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.*;
import org.bouncycastle.math.ec.ECPoint;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class TestWallet extends LTBCMainTestCase {

    public static BitcoinAvatarService fromWatchingKey(Network network, DeterministicKey watchKey, ScriptType outputScriptType, BitcoinMasterService masterService) {
        DeterministicKeyChain chain = DeterministicKeyChain.builder().watch(watchKey).outputScriptType(outputScriptType).build();
        return new BitcoinAvatarService(network, KeyChainGroup.builder(network).addChain(chain).build(), masterService);
    }

    record GetWatchingKeyAccept(String watchingKey, Collection<ScriptType> scriptTypes) {
    }

    public static class BitcoinMasterService {
        KeyVaultProxy keyVaultProxy;
        Collection<ScriptType> scriptTypes;
        private final KeyChainGroup wkcg;

        public BitcoinMasterService(Network network, KeyVault kv, Collection<ScriptType> scriptTypes) {
            // The below belongs in the vault
//            KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;
//
//            List<DeterministicKeyChain> keyChains = scriptTypes.stream().map(type -> DeterministicKeyChain.builder()
//                    .seed(seed)
//                    .outputScriptType(type)
//                    .accountPath(kcgs.accountPathFor(type, network))
//                    .build()).toList();
//
//            keyChains.forEach(kc -> {
//                kc.setLookaheadSize(100);
//                kc.maybeLookAhead();
//            });
//
//            KeyChainGroup kcg = KeyChainGroup.builder(network, kcgs).chains(keyChains).build();
            keyVaultProxy = new KeyVaultProxy(kv);

            // now lets play
            //This inits the readonly kcg.
            KeyChainGroup.Builder kcgb = KeyChainGroup.builder(network);
            DeterministicKey watchKey = DeterministicKey.deserializeB58(keyVaultProxy.getWatchingKey(), network);

            for (ScriptType outputScriptType : scriptTypes) {
                DeterministicKeyChain chain = DeterministicKeyChain.builder().watch(watchKey).outputScriptType(outputScriptType).build();
                chain.setLookaheadSize(100);
                chain.maybeLookAhead();
                kcgb.addChain(chain);
            }

            this.wkcg = kcgb.build();
        }


        GetWatchingKeyAccept getWatchingKey() {
            return new GetWatchingKeyAccept(
                    keyVaultProxy.getWatchingKey(),
                    scriptTypes);
        }

        BitcoinTransactionSignatureAccept signTransaction(BitcoinTransactionSignatureRequest request) {
            Transaction transaction = Transaction.read(ByteBuffer.wrap(request.tx));

            // Convert the binary map into Objects
            Map<Sha256Hash, Transaction> transactionMap = request.map.entrySet().stream().collect(Collectors.toUnmodifiableMap(
                    entry -> Sha256Hash.wrap(entry.getKey()),
                    entry -> Transaction.read(ByteBuffer.wrap(entry.getValue()))));

            // Connect the inputs in the request to the outputs
            transaction.getInputs().forEach(ti -> {
                ti.connect(transactionMap.get(ti.getOutpoint().hash()).getOutput(ti.getOutpoint().index()));
            });

            // Prompts the user

            //Yey, we are
            TransactionSigner.ProposedTransaction pt = new TransactionSigner.ProposedTransaction(transaction);

//            keyVaultProxy.keyVault.zsignTransaction(pt.partialTx);
//            zsignTransaction(pt.partialTx);
            keyVaultProxy.signInputs(pt, this.wkcg);
//
//            keyVaultProxy.keyVault.signInputs(pt);
            return new BitcoinTransactionSignatureAccept(transaction.serialize());
        }

        public void zsignTransaction(Transaction tx) throws Wallet.BadWalletEncryptionKeyException {
            try {
                List<TransactionInput> inputs = tx.getInputs();
                List<TransactionOutput> outputs = tx.getOutputs();
                Preconditions.checkState(inputs.size() > 0);
                Preconditions.checkState(outputs.size() > 0);

//                KeyBag maybeDecryptingKeyBag = new DecryptingKeyBag(internalWallet, req.aesKey);
                KeyBag maybeDecryptingKeyBag = this.wkcg;

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

    }

    record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
    }

    record BitcoinTransactionSignatureAccept(byte[] tx) {
    }

    static class KeyVaultProxy extends LocalTransactionSigner {
        private static final Logger log = LoggerFactory.getLogger(KeyVaultProxy.class);
        KeyVault keyVault;

        public KeyVaultProxy(KeyVault keyVault) {
            this.keyVault = keyVault;
        }

        private static final EnumSet<Script.VerifyFlag> MINIMUM_VERIFY_FLAGS;

        static {
            MINIMUM_VERIFY_FLAGS = EnumSet.of(Script.VerifyFlag.P2SH, Script.VerifyFlag.NULLDUMMY);
        }

        static class WrapedEcKey extends ECKey {
            private final KeyVault vault;

            public WrapedEcKey(ECPoint pub, boolean compressed, KeyVault keyVault) {
                super(null, pub, compressed);
                this.vault = keyVault;
            }

            @Override
            public ECDSASignature sign(Sha256Hash input, @Nullable AesKey aesKey) throws KeyCrypterException {
//                return super.sign(input, aesKey);
                return vault.sign(input, getPubKeyHash());
            }
        }

        public boolean signInputs(TransactionSigner.ProposedTransaction propTx, KeyBag keyBag) {
            Transaction tx = propTx.partialTx;
            int numInputs = tx.getInputs().size();

            for (int i = 0; i < numInputs; ++i) {
                TransactionInput txIn = tx.getInput((long) i);
                TransactionOutput connectedOutput = txIn.getConnectedOutput();
                if (connectedOutput == null) {
                    log.warn("Missing connected output, assuming input {} is already signed.", i);
                } else {
                    Script scriptPubKey = connectedOutput.getScriptPubKey();

                    try {
                        txIn.getScriptSig().correctlySpends(tx, i, txIn.getWitness(), connectedOutput.getValue(), connectedOutput.getScriptPubKey(), MINIMUM_VERIFY_FLAGS);
                        log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                    } catch (ScriptException var19) {
                        RedeemData redeemData = txIn.getConnectedRedeemData(keyBag);
                        ECKey pubKey = (ECKey) redeemData.keys.get(0);
                        if (pubKey instanceof DeterministicKey) {
                            propTx.keyPaths.put(scriptPubKey, ((DeterministicKey) pubKey).getPath());
                        }

                        //Here we need to call the vault and get a signature
                        {
//                            ECKey key = redeemData.getFullKey();
                            ECKey key = new WrapedEcKey(pubKey.getPubKeyPoint(), pubKey.isCompressed(), keyVault);

                            if (key == null) {
                                log.warn("No local key found for input {}", i);
                            } else {
                                Script inputScript = txIn.getScriptSig();
                                byte[] script = redeemData.redeemScript.program();

                                try {
                                    // Now witness version
                                    if (!ScriptPattern.isP2PK(scriptPubKey) && !ScriptPattern.isP2PKH(scriptPubKey) && !ScriptPattern.isP2SH(scriptPubKey)) {
                                        if (!ScriptPattern.isP2WPKH(scriptPubKey)) {
                                            throw new IllegalStateException(script.toString());
                                        }

                                        Script scriptCode = ScriptBuilder.createP2PKHOutputScript(key);
                                        Coin value = txIn.getValue();
                                        TransactionSignature signature = tx.calculateWitnessSignature(i, key, scriptCode, value, Transaction.SigHash.ALL, false);
                                        txIn = txIn.withScriptSig(ScriptBuilder.createEmpty());
                                        txIn = txIn.withWitness(TransactionWitness.redeemP2WPKH(signature, key));

                                        // We have no witness
                                    } else {
                                        TransactionSignature signature = tx.calculateSignature(i, key, script, Transaction.SigHash.ALL, false);
                                        int sigIndex = 0;
                                        inputScript = scriptPubKey.getScriptSigWithSignature(inputScript, signature.encodeToBitcoin(), sigIndex);
                                        txIn = txIn.withScriptSig(inputScript);
                                        txIn = txIn.withoutWitness();
                                    }
                                } catch (ECKey.KeyIsEncryptedException e) {
                                    throw e;
                                } catch (ECKey.MissingPrivateKeyException var18) {
                                    log.warn("No private key in keypair for input {}", i);
                                }

                                tx.replaceInput(i, txIn);
                            }
                        }

                    }
                }
            }

            return true;
        }

//        void zfunc(TransactionInput txIn, RedeemData redeemData, ECKey pubKey, Script scriptPubKey) {
//            {
//                ECKey key = redeemData.getFullKey();
//                if (key == null) {

        /// /                    log.warn("No local key found for input {}", i);
//                } else {
//                    Script inputScript = txIn.getScriptSig();
//                    byte[] script = redeemData.redeemScript.program();
//
//                    try {
//                        // Now witness version
//                        if (!ScriptPattern.isP2PK(scriptPubKey) && !ScriptPattern.isP2PKH(scriptPubKey) && !ScriptPattern.isP2SH(scriptPubKey)) {
//                            if (!ScriptPattern.isP2WPKH(scriptPubKey)) {
//                                throw new IllegalStateException(script.toString());
//                            }
//
//                            Script scriptCode = ScriptBuilder.createP2PKHOutputScript(key);
//                            Coin value = txIn.getValue();
//                            TransactionSignature signature = tx.calculateWitnessSignature(i, key, scriptCode, value, Transaction.SigHash.ALL, false);
//                            txIn = txIn.withScriptSig(ScriptBuilder.createEmpty());
//                            txIn = txIn.withWitness(TransactionWitness.redeemP2WPKH(signature, key));
//
//                            // We have a witness
//                        } else {
//                            TransactionSignature signature = tx.calculateSignature(i, key, script, Transaction.SigHash.ALL, false);
//                            int sigIndex = 0;
//                            inputScript = scriptPubKey.getScriptSigWithSignature(inputScript, signature.encodeToBitcoin(), sigIndex);
//                            txIn = txIn.withScriptSig(inputScript);
//                            txIn = txIn.withoutWitness();
//                        }
//                    } catch (ECKey.KeyIsEncryptedException e) {
//                        throw e;
//                    } catch (ECKey.MissingPrivateKeyException var18) {
//                        log.warn("No private key in keypair for input {}", i);
//                    }
//
//                    tx.replaceInput(i, txIn);
//                }
//            }
//        }


//        @Override
//        public boolean isReady() {
//            return keyVault != null;
//        }
//
//        @Override
//        public boolean signInputs(ProposedTransaction proposedTransaction, KeyBag keyBag) {
//            return keyVault.signInputs(proposedTransaction);
//        }
        public String getWatchingKey() {
            return keyVault.getWatchingKey();
        }

//        @Override
//        protected SignatureAndKey getSignature(Sha256Hash sha256Hash, List<ChildNumber> list) {
//            return keyVault.getSignature(sha256Hash, list);
//        }
    }

    static class BitcoinAvatarService {

        final private Wallet wallet;
        final private BitcoinMasterService masterService;

        public BitcoinAvatarService(Network network, KeyChainGroup keyChainGroup, BitcoinMasterService masterService) {
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
            BitcoinTransactionSignatureRequest request = new BitcoinTransactionSignatureRequest(tx.serialize(), map);

            // The master receives the request and signs it
            BitcoinTransactionSignatureAccept accept = masterService.signTransaction(request);
            return Transaction.read(ByteBuffer.wrap(accept.tx));
        }
    }

    @SneakyThrows
    @Test
    void testSendMoney() {
        RegTestParams params = RegTestParams.get();
        ScriptType scriptType = ScriptType.P2PKH;

        String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
//        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 512, "");

        List<ScriptType> scriptTypes = List.of(scriptType);
        KeyVault kv = new KeyVault(params.network(), ds, scriptTypes);
        BitcoinMasterService aliceBitcoinMasterService = new BitcoinMasterService(params.network(), kv, scriptTypes);

        // TODO, this is a bit of a hack we crate a kit and then add a second wallet, discarding the first
        Path tmpDir = Files.createTempDirectory("test_");
        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");
        kit.connectToLocalHost();
        kit.startAsync().awaitRunning();

        // Retrieve the WatchingKey to setup the wallet
        GetWatchingKeyAccept wk = aliceBitcoinMasterService.getWatchingKey();
        DeterministicKey watchingKey = DeterministicKey.deserializeB58(wk.watchingKey, params.network());

        BitcoinAvatarService aliceBitcoinAvatarService = fromWatchingKey(params.network(), watchingKey, scriptType, aliceBitcoinMasterService);

        kit.peerGroup().addWallet(aliceBitcoinAvatarService.wallet);
        kit.chain().addWallet(aliceBitcoinAvatarService.wallet);

        Address address = aliceBitcoinAvatarService.wallet.freshReceiveAddress();

        // Make sure the wallet is empty
        Assertions.assertEquals(Coin.valueOf(0), aliceBitcoinAvatarService.wallet.getBalance());

        ltbc.sendTo(address.toString(), 1.0);
        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        // Make sure we got the coins
        Assertions.assertEquals(Coin.valueOf(1, 0), aliceBitcoinAvatarService.wallet.getBalance());

        // Bob creates an address for Alice
        Path bobsTempDir = Files.createTempDirectory("test2_");
        WalletAppKit bobsKit = new WalletAppKit(params, bobsTempDir.toFile(), "test");
        bobsKit.connectToLocalHost();
        bobsKit.startAsync().awaitRunning();

        Address bobsAddress = bobsKit.wallet().freshReceiveAddress();

        // The Avatar creates a SR
        SendRequest sr = SendRequest.to(bobsAddress, Coin.valueOf(0, 7));
        sr.signInputs = false;
        aliceBitcoinAvatarService.wallet.completeTx(sr);
//        aliceBitcoinAvatarService.masterService.zsignTransaction(sr.tx);


        // The Avatar reads the response off wire and sends it out on network
        Transaction tx3 = aliceBitcoinAvatarService.signTransaction(sr.tx);
        kit.peerGroup().broadcastTransaction(tx3);

        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        Assertions.assertEquals(92977300, aliceBitcoinAvatarService.wallet.getBalance().longValue());
        Assertions.assertEquals(7000000, bobsKit.wallet().getBalance().longValue());
//        System.out.println(ww.getBalance());
//        System.out.println(kit2.wallet().getBalance());

        System.out.println("The END");
    }
}
