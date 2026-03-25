package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.util.WalletHelper;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class TestWallet3 extends LTBCMainTestCase {

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
        private final Network network;

        public BitcoinMasterService(Network network, KeyVault keyVault, Collection<ScriptType> scriptTypes) {
            this.network = network;
//        public BitcoinMasterService(Network network, DeterministicSeed seed, Collection<ScriptType> scriptTypes) {
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
            keyVaultProxy = new KeyVaultProxy(keyVault, network);

            // now lets play
            //This inits the readonly kcg.
            KeyChainGroup.Builder kcgb = KeyChainGroup.builder(network);
            KeyVault.BitcoinGetWatchingKeyCallConfig callConfig = new KeyVault.BitcoinGetWatchingKeyCallConfig(network, scriptTypes.stream().findFirst().orElseThrow());
            DeterministicKey watchKey = DeterministicKey.deserializeB58(keyVaultProxy.getWatchingKey(callConfig), network);

            for (ScriptType outputScriptType : scriptTypes) {
                DeterministicKeyChain chain = DeterministicKeyChain.builder().watch(watchKey).outputScriptType(outputScriptType).build();
                chain.setLookaheadSize(100);
                chain.maybeLookAhead();
                kcgb.addChain(chain);
            }

            this.wkcg = kcgb.build();
            this.scriptTypes = scriptTypes;
        }

        GetWatchingKeyAccept getWatchingKey() {
            KeyVault.BitcoinGetWatchingKeyCallConfig callConfig = new KeyVault.BitcoinGetWatchingKeyCallConfig(network, scriptTypes.stream().findFirst().orElseThrow());

            return new GetWatchingKeyAccept(
                    keyVaultProxy.getWatchingKey(callConfig),
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

        final Network network;

        public KeyVaultProxy(KeyVault keyVault, Network network) {
            this.keyVault = keyVault;
            this.network = network;
        }

        private static final EnumSet<Script.VerifyFlag> MINIMUM_VERIFY_FLAGS;

        static {
            MINIMUM_VERIFY_FLAGS = EnumSet.of(Script.VerifyFlag.P2SH, Script.VerifyFlag.NULLDUMMY);
        }

        static class WrapedEcKey extends ECKey {
            private final KeyVaultProxy keyVaultProxy;
            private final ScriptType scriptType;
//            private final KeyVault vault;


            public WrapedEcKey(ECPoint pub, boolean compressed, KeyVaultProxy keyVaultProxy, ScriptType scriptType) {
                super(null, pub, compressed);
                this.keyVaultProxy = keyVaultProxy;
                this.scriptType = scriptType;
            }

            @Override
            public ECDSASignature sign(Sha256Hash input, @Nullable AesKey aesKey) throws KeyCrypterException {
//            public ECDSASignature sign(Sha256Hash input, @Nullable AesKey aesKey) throws KeyCrypterException {
//                return super.sign(input, aesKey);
//                KeyVault.BitcoinECDSASignCallConfig callConfig = new KeyVault.BitcoinECDSASignCallConfig();

                return keyVaultProxy.sign(this.getPubKeyHash(), input, scriptType);
            }
        }

        private ECKey.ECDSASignature sign(byte[] pubKeyHash, Sha256Hash input, ScriptType scriptType) {
            KeyVault.BitcoinECDSASignCallConfig callConfig = new KeyVault.BitcoinECDSASignCallConfig(network, scriptType, input.getBytes(), null, pubKeyHash);
            return keyVault.sign(callConfig);
        }

        public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
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
                            ScriptType scriptType = redeemData.redeemScript.getScriptType();
                            ECKey key = new WrapedEcKey(pubKey.getPubKeyPoint(), pubKey.isCompressed(), this, scriptType);

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
        public String getWatchingKey(KeyVault.BitcoinGetWatchingKeyCallConfig callConfig) {
            return keyVault.getWatchingKey(callConfig);
        }

//        @Override
//        protected SignatureAndKey getSignature(Sha256Hash sha256Hash, List<ChildNumber> list) {
//            return keyVault.getSignature(sha256Hash, list);
//        }
    }

    static class KeyVault {
        //        private final Wallet internalWallet;
//        private final LocalTransactionSigner lts;
//        private final KeyChainGroup kcg;
//        private final DeterministicSeed seed;
        private final ArrayList<DeterministicSeed> masterSeeds = new ArrayList<>();
        private final Map<Integer, AbstractCallHandler> callMap = new HashMap<>();


        public KeyVault(DeterministicSeed seed) {
//        public KeyVault(Network network, KeyChainGroup kcg) {
//            this.kcg = kcg;
//            this.internalWallet = new Wallet(network, kcg);
//            this.lts = new LocalTransactionSigner();
            this.masterSeeds.add(seed);
        }

        String getWatchingKey(BitcoinGetWatchingKeyCallConfig callConfig) {

            // TODO: This is very very much an ugly hack!
            AbstractBitcoinCallHandler.GetWatchingKeyCallHandler callHandler = new AbstractBitcoinCallHandler.GetWatchingKeyCallHandler();
            this.callMap.put(callConfig.callId, callHandler);

            byte[] callRes = this.call(0, "bob@teahouse.com", "bitcoin", "HelloWorld".getBytes(StandardCharsets.UTF_8), callConfig);

            return new String(callRes, StandardCharsets.UTF_8);
        }

        @SneakyThrows
        public ECKey.ECDSASignature sign(BitcoinECDSASignCallConfig callConfig) {

            // TODO: This is very very much an ugly hack!
            AbstractBitcoinCallHandler.ECDSASignCallHandler callHandler = new AbstractBitcoinCallHandler.ECDSASignCallHandler();
            this.callMap.put(callConfig.callId, callHandler);

//            DeterministicKey keyFromPubHash = kcg.getActiveKeyChain().findKeyFromPubHash(pubKeyHash);
//            ECKey.ECDSASignature sign = keyFromPubHash.sign(input);

            byte[] callRes = this.call(0, "bob@teahouse.com", "bitcoin", "HelloWorld".getBytes(StandardCharsets.UTF_8), callConfig);
            return ECKey.ECDSASignature.decodeFromDER(callRes);
        }


        abstract static class CallConfig {
            final int callId;

            CallConfig(int callId) {
                this.callId = callId;
            }
        }

        // GPG
        // SSH
        // X509
        // Nostr
        // Bitcoin

        abstract static class BitcoinCallConfig extends CallConfig {
            static int BITCOIN_CALL_OFFSET = 0x0050;

            final Network network;
            final public ScriptType scriptType;


            BitcoinCallConfig(int callId, Network network, ScriptType scriptType) {
                super(BITCOIN_CALL_OFFSET + callId);
                this.network = network;
                this.scriptType = scriptType;
            }
        }

        static class BitcoinGetWatchingKeyCallConfig extends BitcoinCallConfig {

            BitcoinGetWatchingKeyCallConfig(Network network, ScriptType type) {
                super(0x0000, network, type);
            }
        }

        static class BitcoinECDSASignCallConfig extends BitcoinCallConfig {
            final public byte[] pubKeyHash;
            final public byte[] hash;

            BitcoinECDSASignCallConfig(Network network, ScriptType type, byte[] hash, String path, byte[] pubKeyHash) {
                super(0x0001, network, type);
                this.hash = hash;
                this.pubKeyHash = pubKeyHash;
            }
        }

        public byte[] call(int masterSeedId, String id, String protocol, byte[] configHash, CallConfig callConfig) {
            //Generate the correct seed
            DeterministicSeed idSeed = WalletHelper.createSubSeed(masterSeeds.get(masterSeedId), id, "");
            DeterministicSeed protocolSeed = WalletHelper.createSubSeed(idSeed, protocol, "");
            DeterministicSeed configurationSeed = WalletHelper.createSubSeed(idSeed, configHash, "");

            System.out.println(Base64.getEncoder().encodeToString(configurationSeed.getSeedBytes()));

            //Process the call
            return callMap.get(callConfig.callId).handelCall(configurationSeed, callConfig);
        }

        public static abstract class AbstractCallHandler {
            abstract byte[] handelCall(DeterministicSeed seed, CallConfig callConfig);
        }

        public static abstract class AbstractBitcoinCallHandler extends AbstractCallHandler {
            Network network;
            ScriptType type;
            DeterministicKeyChain dkc;

            @Override
            byte[] handelCall(DeterministicSeed seed, CallConfig abstractCallConfig) {
                BitcoinCallConfig callConfig = (BitcoinCallConfig) abstractCallConfig;

                this.network = callConfig.network;
                this.type = callConfig.scriptType;

                // The below belongs in the vault
                KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;

                // TODO define keychains to use
                dkc = DeterministicKeyChain.builder()
                        .seed(seed)
                        .outputScriptType(type)
                        .accountPath(kcgs.accountPathFor(type, network))
                        .build();

                dkc.setLookaheadSize(100);
                dkc.maybeLookAhead();

                return new byte[0];
            }

            public static class GetWatchingKeyCallHandler extends AbstractBitcoinCallHandler {
                @Override
                byte[] handelCall(DeterministicSeed seed, CallConfig abstractCallConfig) {
                    super.handelCall(seed, abstractCallConfig);
                    BitcoinGetWatchingKeyCallConfig callConfig = (BitcoinGetWatchingKeyCallConfig) abstractCallConfig;

                    return dkc.getWatchingKey().serializePubB58(network).getBytes();
                }
            }

            public static class ECDSASignCallHandler extends AbstractBitcoinCallHandler {
                @Override
                byte[] handelCall(DeterministicSeed seed, CallConfig abstractCallConfig) {
                    super.handelCall(seed, abstractCallConfig);
                    BitcoinECDSASignCallConfig callConfig = (BitcoinECDSASignCallConfig) abstractCallConfig;

                    DeterministicKey key = dkc.findKeyFromPubHash(callConfig.pubKeyHash);
                    ECKey.ECDSASignature sign = key.sign(Sha256Hash.of(callConfig.hash));
                    return sign.encodeToDER();
                }
            }
        }
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
//        DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");
//        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 512, "");

        // Here we crate the stupp, so we should creat a propper KeyVault Here based on the magic words.

        KeyVault kv = new KeyVault(DeterministicSeed.ofMnemonic(mn, ""));
        BitcoinMasterService aliceBitcoinMasterService = new BitcoinMasterService(params.network(), kv, List.of(scriptType));

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
