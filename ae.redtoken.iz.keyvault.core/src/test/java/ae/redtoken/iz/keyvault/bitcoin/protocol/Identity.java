package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import lombok.SneakyThrows;

import java.util.HashMap;
import java.util.Map;

public class Identity {
    static Map<String, Class<? extends Protocol>> protocolFacktory = new HashMap<>();

    static {
        protocolFacktory.put(BitcoinProtocol.protocolId, BitcoinProtocol.class);
    }

    public final String id;
    public final Map<String, Protocol> protocols = new HashMap<>();

    public Identity(String id) {
        this.id = id;
    }

    @SneakyThrows
    public Protocol getProtocol(String protocolId) {
        if (!protocols.containsKey(protocolId)) {
            Protocol protocol = protocolFacktory.get(protocolId).getConstructor().newInstance();
            protocols.put(protocolId, protocol);
        }
        return protocols.get(protocolId);
    }
}
