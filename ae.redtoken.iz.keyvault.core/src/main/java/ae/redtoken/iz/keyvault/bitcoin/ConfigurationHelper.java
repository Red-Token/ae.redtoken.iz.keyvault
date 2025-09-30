package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.SneakyThrows;

public class ConfigurationHelper {
    @SneakyThrows
    public static String toJSON(Object object) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        return mapper.writeValueAsString(object);
    }

    static byte[] hash(Object object) {
        return WalletHelper.mangle(toJSON(object));
    }
}
