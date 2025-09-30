package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.KeyChainGroupStructure;

import java.util.Collection;
import java.util.Objects;

public final class BitcoinConfiguration {
    public BitcoinNetwork network;
    public BitcoinKeyGenerator keyGenerator;
    public Collection<ScriptType> scriptTypes;

    public BitcoinConfiguration(BitcoinNetwork network, BitcoinKeyGenerator keyGenerator,
                                Collection<ScriptType> scriptTypes) {
        this.network = network;
        this.keyGenerator = keyGenerator;
        this.scriptTypes = scriptTypes;
    }

    public BitcoinConfiguration() {
    }

    public BitcoinNetwork network() {
        return network;
    }

    public BitcoinKeyGenerator keyGenerator() {
        return keyGenerator;
    }

    public Collection<ScriptType> scriptTypes() {
        return scriptTypes;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (BitcoinConfiguration) obj;
        return Objects.equals(this.network, that.network) &&
                Objects.equals(this.keyGenerator, that.keyGenerator) &&
                Objects.equals(this.scriptTypes, that.scriptTypes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(network, keyGenerator, scriptTypes);
    }

    @Override
    public String toString() {
        return "BitcoinConfiguration[" +
                "network=" + network + ", " +
                "keyGenerator=" + keyGenerator + ", " +
                "scriptTypes=" + scriptTypes + ']';
    }

    public enum BitcoinKeyGenerator {
        BIP32(KeyChainGroupStructure.BIP32),
        BIP43(KeyChainGroupStructure.BIP43);

        public final KeyChainGroupStructure kcgs;

        BitcoinKeyGenerator(KeyChainGroupStructure kcgs) {
            this.kcgs = kcgs;
        }
    }
}
