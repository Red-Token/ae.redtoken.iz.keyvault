package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.io.File;
import java.lang.reflect.Constructor;

public class BitcoinProtocolStackedService extends AbstractProtocolStackedService {
    public static String PROTOCOL_ID = "bitcoin";

    public BitcoinProtocolStackedService(IdentityStackedService parent) {
        super(parent, PROTOCOL_ID);
    }

    @Override
    public Class<? extends AbstractConfigurationStackedService> getConfigurationStackedServiceClass() {
        return BitcoinConfigurationStackedService.class;
    }
}
