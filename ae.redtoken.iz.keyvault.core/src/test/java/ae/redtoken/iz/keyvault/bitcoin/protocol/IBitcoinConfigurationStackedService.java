package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.IStackedService;

public interface IBitcoinConfigurationStackedService extends IStackedService {
    BitcoinProtocolM.GetWatchingKeyAccept getWatchingKey();
    BitcoinProtocolM.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolM.BitcoinTransactionSignatureRequest request);
}
