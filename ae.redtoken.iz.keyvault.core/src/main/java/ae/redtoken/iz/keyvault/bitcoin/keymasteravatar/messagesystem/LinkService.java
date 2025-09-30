package ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public abstract class LinkService implements Runnable {
    static ObjectMapper mapper = new ObjectMapper();

//    static {
//        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
//    }

}
