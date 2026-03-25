package ae.redtoken.iz.keyvault.protocols;

import ae.redtoken.util.Util;
import ae.redtoken.util.WalletHelper;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.File;
import java.nio.file.Path;
import java.util.HexFormat;

public class AbstractConfiguration<P extends AbstractProtocol<P,M>,M extends AbstractProtocolMetaData> {
    @SneakyThrows
    protected static <X extends AbstractProtocolMetaData> X loadFromFile(Path path, Class<X> cls) {
        ObjectMapper mapper = new ObjectMapper();
        File file = path.resolve(".config.json").toFile();
        return mapper.readValue(file, cls);
    }

    public final P protocol;
    public final M metaData;
    public final String name;
    public final DeterministicSeed seed;

    @SneakyThrows
    public AbstractConfiguration(P protocol, M metaData) {
        this.protocol = protocol;
        this.metaData = metaData;

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        String str = mapper.writeValueAsString(metaData);
        this.name = Util.bytesToHex(Sha256Hash.of(str.getBytes()).getBytes());
        this.seed = WalletHelper.createSubSeed(protocol.seed, str, "");
        protocol.configurations.put(name,this);
    }
}
