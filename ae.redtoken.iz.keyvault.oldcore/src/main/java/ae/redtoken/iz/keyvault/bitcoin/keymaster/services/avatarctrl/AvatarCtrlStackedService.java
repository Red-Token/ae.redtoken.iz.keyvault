package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.avatarctrl;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AvatarCtrlStackedService extends StackedService implements IAvatarCtrlService {

    @Override
    public AvatarCtrlMessages.AvatarCtrlLoginAccept login(AvatarCtrlMessages.AvatarCtrlLoginRequest request) {

        log.trace("login");

        return new AvatarCtrlMessages.AvatarCtrlLoginAccept(new String[]{});
    }
}