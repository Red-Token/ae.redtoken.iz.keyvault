package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import ae.redtoken.iz.keyvault.bitcoin.ConfigurationHelper;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;

public class SshConfigurationStackedService extends AbstractConfigurationStackedService implements ISshConfigurationService {
    public final SshConfiguration config;
    private final KeyVaultProxy.SshProtocolExecutor executor;
//    private final KeyChainGroup wkcg;

    public SshConfigurationStackedService(SshProtocolStackedService parent, SshConfiguration config) {
        super(parent, new String(WalletHelper.mangle(ConfigurationHelper.toJSON(config))));
        this.config = config;
        this.executor = parent.parent.proxy.new SshProtocolExecutor(config);
    }

    @SneakyThrows
    @Override
    public SshProtocolMessages.SshGetPublicKeyAccept getPublicKey() {
        String publicKey = executor.getPublicKey();
        return new SshProtocolMessages.SshGetPublicKeyAccept(publicKey);
    }

    @Override
    public SshProtocolMessages.SshSignEventAccept signEvent(SshProtocolMessages.SshSignEventRequest request) {
        String signature = executor.sign(request.publicKey(), request.data());
        return new SshProtocolMessages.SshSignEventAccept(signature);
    }
}
