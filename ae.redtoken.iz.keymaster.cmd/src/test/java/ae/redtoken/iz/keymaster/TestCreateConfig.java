package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

public class TestCreateConfig {

    static class ConfigFactory {
    }

    @SneakyThrows
    @Test
    void testConfig() {
        BitcoinNetwork network = BitcoinNetwork.REGTEST;
        ScriptType scriptType = ScriptType.P2PKH;
        List<ScriptType> scriptTypes = List.of(scriptType);

        File fs = new File("/tmp/zol.json");


        BitcoinConfiguration bitconf = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
        ObjectMapper om =  new ObjectMapper();
        om.writeValue(fs, bitconf);

        BitcoinConfiguration bc = om.readValue(fs, BitcoinConfiguration.class);

        System.out.println(om.writeValueAsString(bc));


    }
}
