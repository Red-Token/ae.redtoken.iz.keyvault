package ae.redtoken.iz.keyvault.bitcoin.stackedservices.test;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import ae.redtoken.iz.keyvault.bitcoin.protocol.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.protocol.IdentityStackedService;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.AvatarRunnable;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.MasterRunnable;
import ae.redtoken.iz.keyvault.bitcoin.stackedservices.StackedService;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class TestMessageBus {

    interface IKeyMaster {
        String getDefaultId();

        String[] getIdentities();
    }

    public static class KeyMasterService extends StackedService implements IKeyMaster {

        @Override
        public String getDefaultId() {
            return subServices.keySet().stream().findFirst().orElse(null);
        }

        @Override
        public String[] getIdentities() {
            return subServices.keySet().toArray(new String[0]);
        }

        final KeyVault kv;
        final KeyMasterStackedService km;

        public KeyMasterService(Network network) {
            super(null, null);

            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");

            this.kv = new KeyVault(network, ds);
            this.km = new KeyMasterStackedService(kv);
        }

//        @Override
//        protected String getIdString() {
//            return "";
//        }
    }

    interface IIdentity {
        String[] getProtocols();
    }

    public static class IdentityService extends StackedService implements IIdentity {
        IdentityStackedService identity;

        public IdentityService(KeyMasterStackedService km, String id) {
            super(km, id);
            this.identity = new IdentityStackedService(km, id);
        }

        @Override
        public String[] getProtocols() {
            return subServices.keySet().toArray(new String[0]);
        }

//        @Override
//        protected String getIdString() {
//            return identity.id;
//        }
    }

    interface IProtocol {
        String[] getConfigurations();
    }

    abstract public static class ProtocolService extends StackedService implements IProtocol {
        public ProtocolService(IdentityService parent, String id) {
            super(parent, id);
        }

        @Override
        public String[] getConfigurations() {
            return subServices.keySet().toArray(new String[0]);
        }
    }

    interface IBitcoinProtocol extends IProtocol {
    }

    public static class BitcoinProtocolService extends ProtocolService {
        static final String PROTOCOL_NAME = "bitcoin";

        public BitcoinProtocolService(IdentityService identityService) {
            super(identityService, PROTOCOL_NAME);
        }
//        @Override
//        protected String getIdString() {
//            return PROTOCOL_NAME;
//        }
    }

    interface IConfiguration {
    }

    public static abstract class ConfigurationService extends StackedService implements IConfiguration {
        public ConfigurationService(StackedService parent, String id) {
            super(parent, id);
        }
    }

    interface IBitcoinConfiguration extends IConfiguration {
        String hello(String name);

    }

    public static class BitcoinConfigurationService extends ConfigurationService implements IBitcoinConfiguration {

        final BitcoinConfiguration bc;

        public BitcoinConfigurationService(BitcoinProtocolService bps, BitcoinConfiguration bc) {
            super(bps, new String(WalletHelper.mangle(TestWallet.ConfigurationHelper.toJSON(bc))));
            this.bc = bc;
        }

        public BitcoinConfigurationService(BitcoinProtocolService bps, BitcoinNetwork network, Collection<ScriptType> scriptTypes) {
            this(bps, new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes));
        }

        @Override
        public String hello(String name) {
            return "hello " + name;
        }

//        @Override
//        protected String getIdString() {
//            return TestWallet.ConfigurationHelper.toJSON(bc);
//        }
    }

    abstract public static class AvatarRunnable2 extends AvatarRunnable<KeyMasterService> {
        IKeyMaster api;

        public AvatarRunnable2(MasterRunnable<KeyMasterService> serviceRunnable) {
            this.masterRunnable = serviceRunnable;
            this.api = createProxy(new String[0], IKeyMaster.class);
        }
    }

    public static class KeyMasterAvatarRunnableTest extends AvatarRunnable2 {

        public KeyMasterAvatarRunnableTest(MasterRunnable<KeyMasterService> serviceRunnable) {
            super(serviceRunnable);
        }

        @SneakyThrows
        @Override
        public void run() {
            Assertions.assertEquals("joe@cool", api.getDefaultId());
            Assertions.assertArrayEquals(ids, api.getIdentities());

            String[] identityAddress = new String[]{api.getDefaultId()};
            IIdentity idApi = createProxy(identityAddress, IIdentity.class);

            List<String> protocols = List.of(idApi.getProtocols());

            String[] protocolAdress = {api.getDefaultId(), protocols.getFirst()};
            IBitcoinProtocol bitcoinApi = createProxy(protocolAdress, IBitcoinProtocol.class);

            List<String> configurations = List.of(bitcoinApi.getConfigurations());
            Assertions.assertEquals(1, configurations.size());

            String[] configurationAdress = new String[]{api.getDefaultId(), protocols.getFirst(), configurations.getFirst()};
            IBitcoinConfiguration theAPI = createProxy(configurationAdress, IBitcoinConfiguration.class);

            System.out.println(theAPI.hello("Jill"));

            System.out.println("THE END!");
        }
    }

    static String[] ids = {"joe@cool", "joe@zool"};

    @SneakyThrows
    @Test
    void zoolTest() {
        MasterRunnable<KeyMasterService> keyMasterRunnable = new MasterRunnable<>(new KeyMasterService(RegTestParams.get().network()));
        Thread serviceThread = new Thread(keyMasterRunnable);
        serviceThread.start();

        for (String id : ids) {
            IdentityService is = new IdentityService(keyMasterRunnable.rootStackedService.km, id);
//            keyMasterRunnable.rootStackedService.subServices.put(id, is);

            BitcoinProtocolService bps = new BitcoinProtocolService(is);
//            is.subServices.put(BitcoinProtocolService.PROTOCOL_NAME, bps);

            ScriptType scriptType = ScriptType.P2PKH;
            List<ScriptType> scriptTypes = List.of(scriptType);
            BitcoinConfigurationService bcs = new BitcoinConfigurationService(bps, BitcoinNetwork.REGTEST, scriptTypes);
            bps.subServices.put("MYCONF", bcs);
        }

        AvatarRunnable2 keyMasterAvatarRunnable = new KeyMasterAvatarRunnableTest(keyMasterRunnable);
        keyMasterAvatarRunnable.masterRunnable = keyMasterRunnable;

        Thread customerThread = new Thread(keyMasterAvatarRunnable);
        customerThread.start();
        customerThread.join();
    }
}