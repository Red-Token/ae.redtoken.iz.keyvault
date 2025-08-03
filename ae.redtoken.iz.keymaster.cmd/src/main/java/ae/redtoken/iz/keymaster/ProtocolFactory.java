package ae.redtoken.iz.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.io.File;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.Map;

public class ProtocolFactory {
    static Map<String, Class<? extends AbstractProtocolStackedService>> constructors = Map.of(
            BitcoinProtocolStackedService.PROTOCOL_ID, BitcoinProtocolStackedService.class
    );

    @SneakyThrows
    public static AbstractProtocolStackedService createProtocolStackedService(String protocolId, IdentityStackedService identity) {
        return constructors.get(protocolId).getDeclaredConstructor(IdentityStackedService.class).newInstance(identity);
    }
}
