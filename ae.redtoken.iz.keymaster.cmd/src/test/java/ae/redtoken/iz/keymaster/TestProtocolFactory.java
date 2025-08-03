package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import lombok.SneakyThrows;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class TestProtocolFactory {

    @SneakyThrows
    @Test
    void name() {

        DeterministicSeed ds = DeterministicSeed.ofEntropy("HelloWorld!".getBytes(StandardCharsets.UTF_8), "");
        KeyVault keyVault = new KeyVault();
        KeyMasterStackedService keyMaster = new KeyMasterStackedService(keyVault);
        IdentityStackedService identity = new IdentityStackedService(keyMaster, "joe@cool");

        AbstractProtocolStackedService protocol = ProtocolFactory.createProtocolStackedService(BitcoinProtocolStackedService.PROTOCOL_ID, identity);





    }
}
