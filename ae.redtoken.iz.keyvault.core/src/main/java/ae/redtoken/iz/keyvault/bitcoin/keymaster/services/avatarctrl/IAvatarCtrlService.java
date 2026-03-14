package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.login;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

interface ILoginService extends IStackedService {
    NostrProtocolMessages.NostrSignEventAccept login(NostrProtocolMessages.NostrSignEventRequest request);
}
    
