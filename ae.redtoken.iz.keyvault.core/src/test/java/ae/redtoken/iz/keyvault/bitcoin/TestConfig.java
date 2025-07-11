package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.Identity;
import ae.redtoken.iz.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.protocols.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.protocols.bitcoin.BitcoinMetaData;
import ae.redtoken.iz.keyvault.protocols.bitcoin.BitcoinProtocol;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;

public class TestConfig {

    @SneakyThrows
    @Test
    void name() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

//        BitcoinMetaData bpc = new BitcoinMetaData(BitcoinMetaData.BitcoinNetwork.regtest, ScriptType.P2PKH, KeyChain.KeyPurpose.RECEIVE_FUNDS);
        BitcoinMetaData bpc = new BitcoinMetaData(BitcoinMetaData.BitcoinNetwork.regtest, ScriptType.P2PKH);

        String str = mapper.writeValueAsString(bpc);

        System.out.println(str);

        BitcoinMetaData bpc2 = mapper.readValue(str, BitcoinMetaData.class);

        DeterministicSeed ds = WalletHelper.generateDeterministicSeed(32, "");

        File seedFile = new File("/var/tmp/test/zool.seed");

        WalletHelper.writeMnemonicWordsToFile(ds, seedFile);

        KeyVault keyVault = KeyVault.fromSeedFile(seedFile, "");

        Identity identity = new Identity(keyVault, "bob@teahouse.com", "Bob");
        BitcoinProtocol protocol = new BitcoinProtocol(identity);
        BitcoinConfiguration config = new BitcoinConfiguration(protocol, bpc2);

        Assertions.assertNotNull(config.seed.getSeedBytes());

        DeterministicKey key = config.keyChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key5 = config.keyChain.getKey(KeyChain.KeyPurpose.REFUND);
        DeterministicKey key1 = config.keyChain.getKey(KeyChain.KeyPurpose.REFUND);

        String serializePubB58 = key1.serializePubB58(bpc.network.params.network());

        System.out.println(key1.getPublicKeyAsHex());

        System.out.println(serializePubB58);
        DeterministicKey deserializeB58 = DeterministicKey.deserializeB58(serializePubB58, bpc.network.params.network());

        System.out.println(deserializeB58.getPublicKeyAsHex());

        Address address = LegacyAddress.fromPubKeyHash(bpc.network.params.network(), key.getPubKeyHash());

        DeterministicKey keyFromPubHash = config.keyChain.findKeyFromPubHash(address.getHash());

        KeyVault keyVault2 = KeyVault.fromSeedFile(seedFile, "");
        Identity identity2 = new Identity(keyVault2, "bob@teahouse.com", "Bob");
        BitcoinProtocol protocol2 = new BitcoinProtocol(identity2);
        BitcoinConfiguration config2 = new BitcoinConfiguration(protocol2, bpc2);

        Assertions.assertArrayEquals(identity.seed.getSeedBytes(), identity2.seed.getSeedBytes());

//        DeterministicKey key3 = config2.keyChain.getKey(KeyChain.KeyPurpose.REFUND);
//        DeterministicKey key4 = config2.keyChain.getKey(KeyChain.KeyPurpose.REFUND);
//        DeterministicKey key2 = config2.keyChain.getKey(KeyChain.KeyPurpose.CHANGE);

//        config2.keyChain.setLookaheadSize(100);
//        config2.keyChain.maybeLookAhead();

        DeterministicKey keyFromPubHash1 = config2.keyChain.findKeyFromPubHash(address.getHash());

        Assertions.assertNotNull(keyFromPubHash1);



//        System.out.println(key2.getPathAsString());

        System.out.println("THE END!");
    }
}
