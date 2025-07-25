package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;
import lombok.SneakyThrows;

import java.util.HashMap;
import java.util.Map;

public class IdentityStackedService extends StackedService {
    static Map<String, Class<? extends AbstractProtocolStackedService>> protocolFacktory = new HashMap<>();

    static {
        protocolFacktory.put(BitcoinProtocolStackedService.PROTOCOL_ID, BitcoinProtocolStackedService.class);
    }

    public final String id;
    public final Map<String, AbstractProtocolStackedService> protocols = new HashMap<>();

    public IdentityStackedService(KeyMasterStackedService km, String id) {
        super(km, id);
        this.id = id;
    }

    @SneakyThrows
    public AbstractProtocolStackedService getProtocol(String protocolId) {
        if (!protocols.containsKey(protocolId)) {
            AbstractProtocolStackedService protocol = protocolFacktory.get(protocolId).getConstructor().newInstance();
            protocols.put(protocolId, protocol);
        }
        return protocols.get(protocolId);
    }

//    @Override
//    protected String getIdString() {
//        return id;
//    }
}
