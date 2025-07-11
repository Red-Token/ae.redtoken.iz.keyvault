package ae.redtoken.iz.keyvault.bitcoin;

import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.*;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
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
        Wallet internalWallet;
        Collection<ScriptType> scriptTypes;

        GetWatchingKeyAccept getWatchingKey() {
            return new GetWatchingKeyAccept(
                    internalWallet.getActiveKeyChain().getWatchingKey().dropParent().dropPrivateBytes()
                            .serializePubB58(internalWallet.network()),
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

            SendRequest sendRequest = SendRequest.forTx(transaction);
            internalWallet.signTransaction(sendRequest);

            // Return the response
            return new BitcoinTransactionSignatureAccept(sendRequest.tx.serialize());
        }

        public BitcoinMasterService(Network network, DeterministicSeed seed, Collection<ScriptType> scriptTypes) {
            KeyChainGroupStructure kcgs = KeyChainGroupStructure.BIP32;

            List<DeterministicKeyChain> keyChains = scriptTypes.stream().map(type -> DeterministicKeyChain.builder()
                    .seed(seed)
                    .outputScriptType(type)
                    .accountPath(kcgs.accountPathFor(type, network))
                    .build()).toList();

            keyChains.forEach(kc -> {
                kc.setLookaheadSize(100);
                kc.maybeLookAhead();
            });

            KeyChainGroup kcg = KeyChainGroup.builder(network, kcgs).chains(keyChains).build();

            this.internalWallet = new Wallet(network, kcg);
        }
    }

    record BitcoinTransactionSignatureRequest(byte[] tx, Map<byte[], byte[]> map) {
    }

    record BitcoinTransactionSignatureAccept(byte[] tx) {
    }

    static class RemoteWalletService {

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

//        @Override
//        public void completeTx(SendRequest req) throws InsufficientMoneyException, TransactionCompletionException {
//            super.completeTx(req);
//        }


        public Transaction signSendRequest(SendRequest sr) {
            // This is how the AvatarService signs a transaction
            byte[] tx = sr.tx.serialize();
            Map<byte[], byte[]> map = new HashMap<>();
            sr.tx.getInputs().forEach(ti -> map.put(ti.getOutpoint().hash().getBytes(),
                    Objects.requireNonNull(Objects.requireNonNull(ti.getConnectedOutput()).getParentTransaction()).serialize()));

            // Create the request and send it over wire
            BitcoinTransactionSignatureRequest request = new BitcoinTransactionSignatureRequest(tx, map);

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

        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 512, "");
        BitcoinMasterService aliceBitcoinMasterService = new BitcoinMasterService(params.network(), ds, List.of(scriptType));


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

        // The Avatar reads the response off wire and sends it out on network
        Transaction tx3 = aliceBitcoinAvatarService.signSendRequest(sr);
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
