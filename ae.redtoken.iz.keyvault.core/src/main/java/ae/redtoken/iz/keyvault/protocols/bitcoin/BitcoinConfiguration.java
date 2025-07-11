package ae.redtoken.iz.keyvault.protocols.bitcoin;

import ae.redtoken.iz.keyvault.protocols.AbstractConfiguration;
import org.bitcoinj.wallet.DeterministicKeyChain;

import java.nio.file.Path;

public class BitcoinConfiguration extends AbstractConfiguration<BitcoinProtocol, BitcoinMetaData> {
    public final DeterministicKeyChain keyChain;

    public BitcoinConfiguration(BitcoinProtocol protocol, BitcoinMetaData metaData) {
        super(protocol, metaData);

        // Create the key chain directly
        this.keyChain = DeterministicKeyChain.builder()
                .seed(this.seed)
                .outputScriptType(metaData.scriptType)
                .build();

        this.keyChain.setLookaheadSize(100);
        this.keyChain.maybeLookAhead();
    }

    public BitcoinConfiguration(BitcoinProtocol protocol, Path path) {
        this(protocol, AbstractConfiguration.loadFromFile(path, BitcoinMetaData.class));
    }
}
