package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedSubService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.io.File;
import java.lang.reflect.Constructor;
import java.util.Arrays;

public abstract class AbstractProtocolStackedService extends StackedSubService<IdentityStackedService> {
    final static ObjectMapper mapper = new ObjectMapper();

    public AbstractProtocolStackedService(IdentityStackedService parent, String id) {
        super(parent, id);
    }

    abstract public Class<? extends AbstractConfigurationStackedService> getConfigurationStackedServiceClass();

    @SneakyThrows
    public AbstractConfigurationStackedService createConfigurationStackedService(File file) {
        Class<? extends AbstractConfigurationStackedService> cssClass = getConfigurationStackedServiceClass();
        Constructor<?> constructor = Arrays.stream(cssClass.getDeclaredConstructors())
                .filter(candidate ->
                        candidate.getParameterTypes().length == 2 && candidate.getParameterTypes()[0].isAssignableFrom(this.getClass()))
                .findFirst()
                .orElseThrow();

        return cssClass.cast(constructor.newInstance(this, mapper.readValue(file,constructor.getParameterTypes()[1])));
    }

}
