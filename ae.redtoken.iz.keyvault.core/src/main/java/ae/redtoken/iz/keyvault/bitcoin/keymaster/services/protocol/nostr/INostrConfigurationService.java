package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

public interface INostrConfigurationService extends IStackedService {
    NostrProtocolMessages.NostrDescribeMessageAccept describe();
    NostrProtocolMessages.NostrGetPublicKeyAccept getPublicKey();
    NostrProtocolMessages.NostrSignEventAccept signEvent(NostrProtocolMessages.NostrSignEventRequest request);
}
