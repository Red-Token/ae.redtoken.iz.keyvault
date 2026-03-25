package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import ae.redtoken.iz.keyvault.bitcoin.stackedservices.IStackedService;

public interface ISshConfigurationService extends IStackedService {
    SshProtocolMessages.SshGetPublicKeyAccept getPublicKey();
    SshProtocolMessages.SshSignEventAccept signEvent(SshProtocolMessages.SshSignEventRequest request);
}
