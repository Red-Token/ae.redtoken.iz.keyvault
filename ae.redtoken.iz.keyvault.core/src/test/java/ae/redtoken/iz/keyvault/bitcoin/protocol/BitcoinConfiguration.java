package ae.redtoken.iz.keyvault.bitcoin.protocol;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.KeyChainGroupStructure;

import java.util.Collection;

public record BitcoinConfiguration(BitcoinNetwork network, BitcoinKeyGenerator keyGenerator,
                                   Collection<ScriptType> scriptTypes) {
    public enum BitcoinKeyGenerator {
        BIP32(KeyChainGroupStructure.BIP32),
        BIP43(KeyChainGroupStructure.BIP43);

        public final KeyChainGroupStructure kcgs;

        BitcoinKeyGenerator(KeyChainGroupStructure kcgs) {
            this.kcgs = kcgs;
        }
    }
}
