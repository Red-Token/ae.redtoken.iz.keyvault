package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

public class ConfigurationHelper {
    @SneakyThrows
    public static String toJSON(Object object) {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(object);
    }

    static byte[] hash(Object object) {
        return WalletHelper.mangle(toJSON(object));
    }
}
