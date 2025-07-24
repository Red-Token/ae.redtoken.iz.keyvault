package ae.redtoken.iz.keyvault.bitcoin.protocol;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMaster;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVault;
import lombok.SneakyThrows;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

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
        final KeyMaster km;

        public KeyMasterService(Network network) {
            String mn = "almost option thing way magic plate burger moral almost question follow light sister exchange borrow note concert olive afraid guard online eager october axis";
            DeterministicSeed ds = DeterministicSeed.ofMnemonic(mn, "");

            this.kv = new KeyVault(network, ds);
            this.km = new KeyMaster(kv);
        }
    }

    interface IIdentity {
        String[] getProtocols();
    }

    static class IdentityService extends StackedService implements IIdentity {
        Identity identity;

        public IdentityService(KeyMaster km, String id) {
            this.identity = new Identity(id);
            km.getIdentities().add(identity);
        }

        @Override
        public String[] getProtocols() {
            return subServices.keySet().toArray(new String[0]);
        }
    }

    interface IProtocol {
        String[] getConfigurations();
    }

    static class ProtocolService extends StackedService implements IProtocol {
        @Override
        public String[] getConfigurations() {
            return subServices.keySet().toArray(new String[0]);
        }
    }

    interface IBitcoinProtocol extends IProtocol {
    }

    static class BitcoinProtocolService extends ProtocolService {
        static final String PROTOCOL_NAME = "bitcoin";
        BitcoinProtocol bp;

        public BitcoinProtocolService(Identity identity) {
            this.bp = (BitcoinProtocol) identity.getProtocol(BitcoinProtocol.protocolId);
        }
    }

    interface IConfiguration {
    }

    static class ConfigurationService extends StackedService implements IConfiguration {
    }

    interface IBitcoinConfiguration extends IConfiguration {
        String hello(String name);

    }

    static class BitcoinConfigurationService extends ConfigurationService implements IBitcoinConfiguration {

        BitcoinConfiguration bc;

        public BitcoinConfigurationService(BitcoinProtocolService bps, Network network, Collection<ScriptType> scriptTypes) {
            this.bc = new BitcoinConfiguration(network, BitcoinConfiguration.BitcoinKeyGenerator.BIP32, scriptTypes);
            bps.bp.configurations.add(bc);
        }

        @Override
        public String hello(String name) {
            return "hello " + name;
        }
    }

    public record Request(AbstractRunnable sender, int id, String[] address, String message) {
    }

    public record Response(String resp) {
    }

    public static class Transaction {
        final Request request;
        final BlockingQueue<Response> response = new ArrayBlockingQueue<>(1);

        public Transaction(Request request) {
            this.request = request;
        }
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
            IdentityService is = new IdentityService(keyMasterRunnable.ss.km, id);
            keyMasterRunnable.ss.subServices.put(id, is);

            BitcoinProtocolService bps = new BitcoinProtocolService(is.identity);
            is.subServices.put(BitcoinProtocolService.PROTOCOL_NAME, bps);

            ScriptType scriptType = ScriptType.P2PKH;
            List<ScriptType> scriptTypes = List.of(scriptType);
            BitcoinConfigurationService bcs = new BitcoinConfigurationService(bps, RegTestParams.get().network(), scriptTypes);
            bps.subServices.put("MYCONF", bcs);
        }

        AvatarRunnable2 keyMasterAvatarRunnable = new KeyMasterAvatarRunnableTest(keyMasterRunnable);
        keyMasterAvatarRunnable.masterRunnable = keyMasterRunnable;

        Thread customerThread = new Thread(keyMasterAvatarRunnable);
        customerThread.start();
        customerThread.join();
    }
}