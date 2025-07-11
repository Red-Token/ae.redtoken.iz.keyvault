package ae.redtoken.iz.keyvault.bitcoin;

import lombok.SneakyThrows;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.base.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class TestWallet2 extends LTBCMainTestCase {

    public static MyWallet fromWatchingKey(Network network, DeterministicKey watchKey, ScriptType outputScriptType, Wallet remoteWallet) {
        DeterministicKeyChain chain = DeterministicKeyChain.builder().watch(watchKey).outputScriptType(outputScriptType).build();
        return new MyWallet(network, KeyChainGroup.builder(network).addChain(chain).build(), remoteWallet);
    }

    static class PryxySigner implements TransactionSigner {

        final TransactionSigner remoteSigner;

        PryxySigner(TransactionSigner remoteSigner) {
            this.remoteSigner = remoteSigner;
        }

        @Override
        public boolean isReady() {
            return remoteSigner.isReady();
        }

        @Override
        public boolean signInputs(ProposedTransaction proposedTransaction, KeyBag keyBag) {
            return remoteSigner.signInputs(proposedTransaction, keyBag);
        }
    }

    static class MyWallet extends Wallet {
        Wallet remoteWallet;

        public MyWallet(Network network, KeyChainGroup keyChainGroup, Wallet remoteWallet) {
            super(network, keyChainGroup);
            this.remoteWallet = remoteWallet;
            addTransactionSigner(new PryxySigner(remoteWallet.getTransactionSigners().getFirst()));
        }

        @Override
        public boolean canSignFor(Script script) {
//            boolean x = super.canSignFor(script);
            boolean y = remoteWallet.canSignFor(script);

            return y;
        }
    }


    @SneakyThrows
    @Test
    void testSendMoney() {
        RegTestParams params = RegTestParams.get();

        DeterministicSeed ds = DeterministicSeed.ofRandom(new SecureRandom(), 512, "");

        DeterministicKeyChain keyChain = DeterministicKeyChain.builder()
                .seed(ds)
                .outputScriptType(ScriptType.P2WPKH)
                .build();

//        KeyChainGroup kcg = KeyChainGroup.builder(params).addChain(keyChain).build();
        Wallet vx2 = Wallet.fromSeed(params.network(), ds, ScriptType.P2PKH);
        vx2.getActiveKeyChain().getWatchingKey();

        List<ECKey> issuedReceiveKeys = vx2.getIssuedReceiveKeys();


        // Set up a wallet
//        Path tmpDir = Files.createTempDirectory("test_");
//        WalletAppKit kit = new WalletAppKit(params, tmpDir.toFile(), "test");

//        kit.connectToLocalHost();
//        kit.startAsync().awaitRunning();

//        Wallet mw = kit.wallet();
        Wallet mw = vx2;

        DeterministicKey watchingKey2 = vx2.getActiveKeyChain().getWatchingKey().dropParent().dropPrivateBytes();
        String serializePubB58 = watchingKey2.serializePubB58(params.network());

        DeterministicKey watchingKey = DeterministicKey.deserializeB58(serializePubB58, params.network());
        ScriptType scriptType = vx2.getActiveKeyChain().getOutputScriptType();

        Path tmpDir2 = Files.createTempDirectory("test2_");
        WalletAppKit kit2 = new WalletAppKit(params, tmpDir2.toFile(), "test");
        kit2.connectToLocalHost();
        kit2.startAsync().awaitRunning();

        MyWallet ww = fromWatchingKey(params.network(), watchingKey, scriptType, mw);

        kit2.peerGroup().addWallet(ww);
        kit2.chain().addWallet(ww);


        ww.addTransactionSigner(mw.getTransactionSigners().getFirst());

        ww.addCoinsReceivedEventListener((wallet, transaction, coin, coin1) -> {
        });

        Address address = ww.freshReceiveAddress();

        vx2.getActiveKeyChain().setLookaheadSize(100);
        vx2.freshReceiveAddress();
        DeterministicKey keyFromPubHash = vx2.getActiveKeyChain().findKeyFromPubHash(address.getHash());

        ww.getIssuedReceiveKeys().forEach(ecKey -> {
            System.out.println(ecKey.isPubKeyOnly());
        });


        // Make sure the wallet is empty
//        Assertions.assertEquals(Coin.valueOf(0), kit.wallet().getBalance());
        Assertions.assertEquals(Coin.valueOf(0), ww.getBalance());

        ltbc.sendTo(address.toString(), 1.0);
        ltbc.mine(6);


        // Wait for the wallet to sync up.
        Thread.sleep(1000);

        // Make sure we got the coins
//        Assertions.assertEquals(Coin.valueOf(1, 0), kit.wallet().getBalance());
        Assertions.assertEquals(Coin.valueOf(1, 0), ww.getBalance());

        Path tmpDir3 = Files.createTempDirectory("test3_");
        WalletAppKit kit3 = new WalletAppKit(params, tmpDir3.toFile(), "test");
        kit3.connectToLocalHost();
        kit3.startAsync().awaitRunning();

        Address address1 = kit3.wallet().freshReceiveAddress();

        SendRequest sr = SendRequest.to(address1, Coin.valueOf(0, 7));
        sr.signInputs = false;
        ww.completeTx(sr);

//        Map<TransactionOutPoint, TransactionOutput> map = new HashMap<>();
        Map<byte[], byte[]> map = new HashMap<>();

        sr.tx.getInputs().forEach(ti -> {
            map.put(ti.getOutpoint().hash().getBytes(), Objects.requireNonNull(Objects.requireNonNull(ti.getConnectedOutput()).getParentTransaction()).serialize());
        });

        System.out.println(sr.tx);

        byte[] transaction = sr.tx.serialize();

        Transaction tx2 = Transaction.read(ByteBuffer.wrap(transaction));

        Map<Sha256Hash, Transaction> map2 = new HashMap<>();

        map.keySet().forEach(rawHash -> {
            Sha256Hash hash = Sha256Hash.wrap(rawHash);
            Transaction tx = Transaction.read(ByteBuffer.wrap(map.get(rawHash)));
            map2.put(hash, tx);
        });

        tx2.getInputs().forEach(ti -> {
            ti.connect(map2.get(ti.getOutpoint().hash()).getOutput(ti.getOutpoint().index()));
//            mw.getUnspents().stream().filter(to -> to.getOutPointFor().equals(ti.getOutpoint())).findFirst().ifPresent(ti::connect);
        });
        System.out.println(tx2);

        Assertions.assertEquals(sr.tx.getTxId(), tx2.getTxId());

//        tx2.getInputs().forEach(ti -> {
//            ti.connect();
//        })

        SendRequest sr2 = SendRequest.forTx(tx2);

        vx2.completeTx(sr2);
//        kit.peerGroup().broadcastTransaction(sr2.tx);


        byte[] txb = sr2.tx.serialize();
//
        Transaction tx3 = Transaction.read(ByteBuffer.wrap(txb));
        kit2.peerGroup().broadcastTransaction(tx3);

        ltbc.mine(6);

        // Wait for the wallet to sync up.
        Thread.sleep(1000);

//        System.out.println(mw.getBalance());
        System.out.println(ww.getBalance());
        System.out.println(kit3.wallet().getBalance());

        System.out.println("The END");
    }
}
