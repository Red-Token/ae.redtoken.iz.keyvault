package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin;

//public interface IBitcoinConfiguration extends IStackedService {
public interface IBitcoinConfiguration {
    BitcoinProtocolMessages.GetWatchingKeyAccept getWatchingKey();
    BitcoinProtocolMessages.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request);
}
