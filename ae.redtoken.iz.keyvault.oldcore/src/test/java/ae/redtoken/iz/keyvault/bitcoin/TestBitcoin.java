package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.ChaCha20SecureRandom;
import ae.redtoken.iz.keyvault.protocols.bitcoin.BitcoinMetaDataOld;
import ae.redtoken.iz.keyvault.protocols.bitcoin.BitcoinNetwork;
import ae.redtoken.lib.PublicKeyAlg;
import ae.redtoken.lib.PublicKeyProtocolMetaData;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class TestBitcoin {

    @SneakyThrows
    @Test
    void name() {

        ObjectMapper mapper = new ObjectMapper();

        BitcoinMetaDataOld bmd = new BitcoinMetaDataOld(
                new PublicKeyProtocolMetaData(PublicKeyAlg.secp256k1_ecdsa, 256),
                BitcoinNetwork.regtest,
                ScriptType.P2PKH,
                KeyChain.KeyPurpose.RECEIVE_FUNDS
        );

        String str = mapper.writeValueAsString(bmd);

        System.out.println(str);

        NetworkParameters parameters = bmd.network.params;

        System.out.println("network params: " + parameters);

        int size = 32;
        String passphrase = "";
        DeterministicSeed ds = WalletHelper.generateDeterministicSeed(size, passphrase);

        Assertions.assertNotNull(ds.getSeedBytes());
        ChaCha20SecureRandom sr = new ChaCha20SecureRandom(ds.getSeedBytes());
//        BitcoinCredentials bc = new BitcoinCredentials(sr, bmd);

        // Create the key chain directly
        DeterministicKeyChain keyChain = DeterministicKeyChain.builder()
                .seed(ds)
                .outputScriptType(ScriptType.P2WPKH)
                .build();

        DeterministicKey key = keyChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);


        KeyPair kp = new KeyPair(new WrapperPubKey(key, parameters.network()), new WrapperPrivateKey(key, parameters.network()));

        System.out.println("THE END!");
    }

    static class X extends KeyPairGeneratorSpi {

        @Override
        public void initialize(int i, SecureRandom secureRandom) {
            secureRandom.getParameters();
        }

        @Override
        public KeyPair generateKeyPair() {
            return null;
        }
    }

    public static record WrapperPubKey(DeterministicKey key, Network network) implements PublicKey {

        @Override
        public String getAlgorithm() {
            return "ECDSA";
        }

        @Override
        public String getFormat() {
            return "Base58";
        }

        @Override
        public byte[] getEncoded() {
            return key.serializePubB58(network).getBytes(StandardCharsets.UTF_8);
        }
    }

    public static record WrapperPrivateKey(DeterministicKey key, Network network) implements PrivateKey {

        @Override
            public String getAlgorithm() {
                return "ECDSA";
            }

            @Override
            public String getFormat() {
                return "Base58";
            }

            @Override
            public byte[] getEncoded() {
                return key.serializePrivB58(network).getBytes(StandardCharsets.UTF_8);
            }
        }
}
