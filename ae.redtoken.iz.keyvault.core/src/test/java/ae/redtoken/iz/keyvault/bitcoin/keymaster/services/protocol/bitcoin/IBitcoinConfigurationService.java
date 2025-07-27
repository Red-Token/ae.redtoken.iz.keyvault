package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

//public interface IBitcoinConfiguration extends IStackedService {
public interface IBitcoinConfigurationService extends IStackedService {
    BitcoinProtocolMessages.GetWatchingKeyAccept getWatchingKey();
    BitcoinProtocolMessages.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request);
}
