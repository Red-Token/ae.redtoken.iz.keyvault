package ae.redtoken.iz.ark.nostrtest;

import com.fasterxml.jackson.databind.ObjectMapper;
import nostr.event.Kind;
import nostr.event.impl.Filters;
import nostr.event.impl.GenericEvent;
import nostr.id.Identity;
import org.bitcoin.tfw.ltbc.tc.LTBCMainTestCase;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.AbstractBitcoinNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.wallet.SendRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Currency;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import static ae.redtoken.iz.ark.nostrtest.TestNostr.RELAYS;

/**
 * Unit test for simple App.
 */
public class AppTest extends LTBCMainTestCase {

    static class Actor {

        WalletAppKit kit;
        Identity identity;

        Actor(AbstractBitcoinNetParams params) {
//            RegTestParams params = RegTestParams.get();

            try {
                kit = new WalletAppKit(params, Files
                        .createTempDirectory("wallet").toFile(), "dat");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            kit.connectToLocalHost();
            kit.startAsync().awaitRunning();

//            kit.wallet().addCoinsReceivedEventListener((wallet, transaction, coin, coin1) -> {
//                System.out.println("Received coin " + coin + " to " + wallet);
//            });

            this.identity = Identity.generateRandomIdentity();
        }
    }

    static class ArkService extends Actor {

        ArkService(AbstractBitcoinNetParams params) {
            super(params);

            kit.wallet().addCoinsReceivedEventListener((wallet, transaction, coin, coin1) -> {
                System.out.println("Received coin " + coin + " to " + wallet);
            });

        }
    }

    static class ArkUser extends Actor {
        ArkUser(AbstractBitcoinNetParams params) {
            super(params);
        }
    }

    static class ArkScriptFactory {

        static Script createVTXONode(ECKey[] userKeys, ECKey serviceKey, int lockTime) {
            ScriptBuilder scriptBuilder = new ScriptBuilder();
            scriptBuilder.op(ScriptOpCodes.OP_IF);

            for (ECKey key : userKeys) {
                scriptBuilder.data(key.getPubKey()).op(ScriptOpCodes.OP_CHECKSIGVERIFY);
            }

            Script redeemScript = scriptBuilder
                    .data(serviceKey.getPubKey())
                    .op(ScriptOpCodes.OP_CHECKSIG)
                    // ELSE (S + Timelock case)
                    .op(ScriptOpCodes.OP_ELSE)
                    .number(lockTime)
                    .op(ScriptOpCodes.OP_CHECKLOCKTIMEVERIFY)
                    .op(ScriptOpCodes.OP_DROP)
                    .data(serviceKey.getPubKey())
                    .op(ScriptOpCodes.OP_CHECKSIG)
                    .op(ScriptOpCodes.OP_ENDIF)
                    .build();
            return redeemScript;
        }

        static Script createVTXOLeaf(ECKey userKey, ECKey serviceKey, int sequenceTime) {
            Script redeemScript = new ScriptBuilder()
                    // IF (A + B case)
                    .op(ScriptOpCodes.OP_IF)
                    .data(userKey.getPubKey())
                    .op(ScriptOpCodes.OP_CHECKSIGVERIFY)
                    .data(serviceKey.getPubKey())
                    .op(ScriptOpCodes.OP_CHECKSIG)
                    // ELSE (A + Timelock case)
                    .op(ScriptOpCodes.OP_ELSE)
                    .number(sequenceTime)
                    .op(ScriptOpCodes.OP_CHECKSEQUENCEVERIFY)
                    .op(ScriptOpCodes.OP_DROP)
                    .data(userKey.getPubKey())
                    .op(ScriptOpCodes.OP_CHECKSIG)
                    .op(ScriptOpCodes.OP_ENDIF)
                    .build();

            return redeemScript;
        }
    }

    @Test
    public void test2() throws Exception {
        RegTestParams params = RegTestParams.get();

        Actor arkService = new ArkService(params);
        ArkUser alice = new ArkUser(params);
        ArkUser bob = new ArkUser(params);
        ArkUser carol = new ArkUser(params);
        ArkUser david = new ArkUser(params);
        ArkUser eve = new ArkUser(params);
        ArkUser freddy = new ArkUser(params);

        ArkUser[] users = Arrays.asList(alice, bob, carol, david, eve, freddy).toArray(new ArkUser[0]);

//        Wallet wallet = arkService.kit.wallet();

        final double coinsToSendToArkService = 10;
        final double coinsToSendToUsers = 1;

        Assertions.assertEquals(Coin.ZERO, arkService.kit.wallet().getBalance());

        this.ltbc.sendTo(arkService.kit.wallet().freshReceiveAddress().toString(), coinsToSendToArkService);

        for (Actor user : users) {
            this.ltbc.sendTo(user.kit.wallet().freshReceiveAddress().toString(), coinsToSendToUsers);
        }

        this.ltbc.mine(6);

        // We wait for 1 second here
        Thread.sleep(1000);

        // TODO fix race condition here
        Assertions.assertEquals(Coin.valueOf((int) coinsToSendToArkService, 0), arkService.kit.wallet().getBalance());

        for (Actor user : users) {
            Assertions.assertEquals(Coin.valueOf((int) coinsToSendToUsers, 0), user.kit.wallet().getBalance());
        }

        // Generate keys
        ECKey keyA = alice.kit.wallet().freshReceiveKey();
        ECKey keyS = arkService.kit.wallet().freshReceiveKey();
        int timeLockBlocks = 10;

        Script redeemScript = ArkScriptFactory.createVTXOLeaf(keyA, keyS, timeLockBlocks);
        Script p2shScript = ScriptBuilder.createP2SHOutputScript(redeemScript);

        Transaction txOut = new Transaction(params);
        TransactionOutput output = txOut.addOutput(Coin.valueOf(1, 0), p2shScript);

        SendRequest sr = SendRequest.forTx(txOut);
        sr.feePerKb = Coin.valueOf(1000);
        arkService.kit.wallet().completeTx(sr);

        arkService.kit.wallet().addWatchedScripts(List.of(p2shScript));
        alice.kit.wallet().addWatchedScripts(List.of(p2shScript));

        arkService.kit.peerGroup().broadcastTransaction(sr.tx);

        Thread.sleep(5000);
        ltbc.mine(6);
        Thread.sleep(5000);

        TransactionOutput to = arkService.kit.wallet().getWatchedOutputs(false).stream()
                .filter(transactionOutput -> transactionOutput.getScriptPubKey().equals(p2shScript))
                .findFirst()
                .orElseThrow();

//        arkService.kit.wallet().getWatchedScripts().forEach(script -> {
//            System.out.println(script.equals(p2shScript));
//        });

//        TransactionOutput to = arkService.kit.wallet().getUnspents().stream().filter(transactionOutput -> transactionOutput.getScriptPubKey().equals(p2shScript)).findFirst().orElseThrow();
        Transaction tx = new Transaction(params);

        tx.addInput(to.getOutPointFor().getConnectedOutput()); // OutPoint from the UTXO (txHash + outputIndex)
        Address recipientAddress = arkService.kit.wallet().freshReceiveAddress();
        tx.addOutput(Coin.valueOf(50000), recipientAddress);

        Sha256Hash sighash = tx.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false);
        TransactionSignature sigA = new TransactionSignature(keyA.sign(sighash), Transaction.SigHash.ALL, false);
        TransactionSignature sigB = new TransactionSignature(keyS.sign(sighash), Transaction.SigHash.ALL, false);

        // This is the dual signature
        Script inputScript = new ScriptBuilder()
                .data(sigB.encodeToBitcoin())
                .data(sigA.encodeToBitcoin())
                .op(ScriptOpCodes.OP_TRUE)
                .data(redeemScript.getProgram())
                .build();

        tx.getInput(0).setScriptSig(inputScript);

        Script outputScript = ScriptBuilder.createP2SHOutputScript(redeemScript);
        tx.getInput(0).getScriptSig().correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        arkService.kit.peerGroup().broadcastTransaction(tx);
        // Broadcast it

        ltbc.mine(6);
        Thread.sleep(5000);

//        var aliceIdentity = Identity.generateRandomIdentity();
//        var eveIdentity = Identity.generateRandomIdentity();

        /**
         *  Step 1: Eve creates a quotation
         */

        ObjectMapper om = new ObjectMapper();
        TestNostr.ArkQuotationContent aqc = new TestNostr.ArkQuotationContent();

        aqc.amount = 30000;
        aqc.pubkey = "WHATEVER";
        aqc.arks.includeOnly = true;
        aqc.arks.include = new String[]{"myarc"};
        aqc.offer.setCurrencyCode(Currency.getInstance("USD").getCurrencyCode());
        aqc.offer.items = new TestNostr.ArkOfferItems[]{
                new TestNostr.ArkOfferItems("Pepperoni", 1, 3.0)
        };
        aqc.offer.vat = "5%";

        String offer = om.writeValueAsString(aqc);
        System.out.println(offer);

        TestNostr.NIP0666<TestNostr.NIP0666ArkQuotationEvent> nip0666Stack = new TestNostr.NIP0666<>();
        nip0666Stack.setSender(eve.identity);
        nip0666Stack.setRelays(RELAYS);
        TestNostr.NIP0666ArkQuotationEventFactory xy = new TestNostr.NIP0666ArkQuotationEventFactory(eve.identity, offer);
        nip0666Stack.setEvent(xy.create());
        nip0666Stack.signAndSend();

        /**
         *  Step 2: Alice scans the bitcoin URL and fetches the offer
         */

        String id = nip0666Stack.getEvent().getId();

        TestNostr.NIP0666<TestNostr.NIP0666ArkQuotationEvent> aliceNip0666Stack = new TestNostr.NIP0666<>();
        aliceNip0666Stack.setRelays(RELAYS);
        aliceNip0666Stack.setSender(alice.identity);
        GenericEvent ge = new GenericEvent();
        ge.setId(id);
        Filters filters2 = Filters.builder().events(List.of(ge)).kinds(List.of(Kind.ARK_QUOTATION)).build();
        String subId2 = "sub_" + alice.identity.getPublicKey();

        BlockingQueue<GenericEvent> queue = new ArrayBlockingQueue<>(1);

        EventCustomHandler2.handlers.put(subId2, (event, message, relay) -> {
            queue.add((GenericEvent) event);
        });

        aliceNip0666Stack.send(filters2, subId2);

        GenericEvent take = queue.take();
        System.out.println(take);


        System.out.println("THE END!");

        /*
         *  Scenario 1
         *
         *  Alice, Bob, Carol, Dave have 1 BTC each in an ARK managed by arkService.
         *
         *  Alice then sends 0.5 BTC to Eve, and Freddy joins the group with 1 BTC. And finally Clare decide she wants to leave with 0.3 BTC.
         *
         *  A new round is created by arkService.
         *
         *  First arkService proposes a new foundation tree.
         *
         *  All parties are then proposes to sign, and fund the nodes in the tree from there current VTXO:s exit transaction.
         *
         *  The makes the root of the round tree valid.
         *
         *  In the second stage tha participants are asked to sign the root nodes of the current round.
         *
         *  Once this is done arkService deposits the tree transition node to the blockchain.
         *
         *  Noster based communication
         *
         *  Eve sends a payment request using a bitcoin uri
         *
         *  bitcoin://#bitcoinaddress#?amount=0.01&lightning=#lightninginvoice#&ark=#npub#
         *
         *  payment request  {
         *      amount: #######
         *      arks: {
         *          include: [ ark1_npub, ark2_npub ]
         *          exclude: [ ark2_npub, ark3_npub ]
         *          will_reject_not_included: true
         *      }
         *      recite {
         *          #description of goods your are paying for#
         *      }
         *  }
         *
         *  payment_offer {
         *      amount: #######
         *      ark: ark2_npub
         *  }
         *
         *  payment_accept {
         *      transaction_key: XXXXXXX
         *  }
         *
         *  payment_recit {
         *      vtxo: [ #transactions# ]
         *  }
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         *
         */


    }
}
