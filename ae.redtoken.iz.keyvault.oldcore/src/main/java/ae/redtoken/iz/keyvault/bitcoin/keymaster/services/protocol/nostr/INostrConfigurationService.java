package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

public interface INostrConfigurationService extends IStackedService {
    NostrProtocolMessages.NostrDescribeMessageAccept describe();
    NostrProtocolMessages.NostrGetPublicKeyAccept getPublicKey();
    NostrProtocolMessages.NostrSignEventAccept signEvent(NostrProtocolMessages.NostrSignEventRequest request);
    NostrProtocolMessages.NostrNip44EncryptEventAccept nip44Encrypt(NostrProtocolMessages.NostrNip44EncryptRequest request);
    NostrProtocolMessages.NostrNip44DecryptEventAccept nip44Decrypt(NostrProtocolMessages.NostrNip44DecryptRequest request);
}
