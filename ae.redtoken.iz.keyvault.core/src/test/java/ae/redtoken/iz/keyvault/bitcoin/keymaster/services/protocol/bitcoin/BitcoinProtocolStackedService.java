package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.identity.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractProtocolStackedService;

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
