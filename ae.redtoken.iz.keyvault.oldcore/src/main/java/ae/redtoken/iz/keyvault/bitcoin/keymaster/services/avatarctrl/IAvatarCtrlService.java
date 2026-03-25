package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.avatarctrl;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr.NostrProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

public interface IAvatarCtrlService extends IStackedService {
    AvatarCtrlMessages.AvatarCtrlLoginAccept login(AvatarCtrlMessages.AvatarCtrlLoginRequest request);
}
    
