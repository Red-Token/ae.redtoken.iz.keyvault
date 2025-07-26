package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

//public interface IBitcoinConfiguration extends IStackedService {
public interface IBitcoinConfiguration {
    BitcoinProtocolM.GetWatchingKeyAccept getWatchingKey();
    BitcoinProtocolM.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolM.BitcoinTransactionSignatureRequest request);
}
