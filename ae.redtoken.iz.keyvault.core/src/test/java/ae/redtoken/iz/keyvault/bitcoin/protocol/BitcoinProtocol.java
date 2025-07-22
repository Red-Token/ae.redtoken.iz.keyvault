package ae.redtoken.iz.keyvault.bitcoin.protocol;

import java.util.ArrayList;
import java.util.Collection;

public class BitcoinProtocol extends Protocol {
    public static String protocolId = "bitcoin";

    public Collection<BitcoinConfiguration> configurations = new ArrayList<>();

    public BitcoinProtocol() {
    }

    @Override
    String getProtocolId() {
        return protocolId;
    }
}
