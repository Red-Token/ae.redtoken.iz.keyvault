package ae.redtoken.iz.keyvault.bitcoin.protocol;

import java.util.ArrayList;
import java.util.Collection;

public class BitcoinProtocolStackedService extends AbstractProtocolStackedService {
    public static String PROTOCOL_ID = "bitcoin";

//    public Collection<BitcoinConfiguration> configurations = new ArrayList<>();

    public BitcoinProtocolStackedService(IdentityStackedService parent) {
        super(parent,  PROTOCOL_ID);
    }

//    @Override
//    protected String getIdString() {
//        return PROTOCOL_ID;
//    }
}
