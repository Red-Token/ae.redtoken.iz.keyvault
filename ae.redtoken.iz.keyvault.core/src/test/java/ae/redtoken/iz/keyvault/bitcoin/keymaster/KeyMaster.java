package ae.redtoken.iz.keyvault.bitcoin.keymaster;

import ae.redtoken.iz.keyvault.bitcoin.TestWallet;

import java.util.ArrayList;
import java.util.Collection;

public class KeyMaster {
    final Collection<TestWallet.Identity> identities = new ArrayList<>();

    public Collection<TestWallet.Identity> getIdentities() {
        return identities;
    }
    public TestWallet.Identity getDefaultIdentity() {
        return identities.iterator().next();
    }


}
