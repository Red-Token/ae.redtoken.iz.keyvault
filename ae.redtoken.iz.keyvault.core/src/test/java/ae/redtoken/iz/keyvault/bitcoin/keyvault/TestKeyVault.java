package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class TestKeyVault {
//public class TestKeyVault extends LTBCMainTestCase {

    interface ITest {
        String hello(String name);

        String getWatchingKey();
        ECKey.ECDSASignature sign(ScriptType scriptType, Sha256Hash input, byte[] pubKeyHash);

    }

    static class TestHandler implements InvocationHandler {
        TestService service;

        @Override
        public Object invoke(Object caller, Method method, Object[] args) throws Throwable {
            return method.invoke(service, args);
        }
    }

    static class TestService implements ITest {
        @Override
        public String hello(String name) {
            return "Hello " + name;
        }

        @Override
        public String getWatchingKey() {
            return "";
        }

        @Override
        public ECKey.ECDSASignature sign(ScriptType scriptType, Sha256Hash input, byte[] pubKeyHash) {
            return null;
        }
    }

    @Test
    void testKeyVault() {
        TestHandler handler = new TestHandler();
        handler.service = new TestService();

        ITest proxy = (ITest) Proxy.newProxyInstance(TestService.class.getClassLoader(), new Class[]{ITest.class}, handler);

        System.out.println(proxy.hello("test"));
    }
}
