package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

abstract public class StackedSubService<A extends StackedService> extends StackedService {
    final public A parent;


    public StackedSubService(A parent, String id) {
        this.parent = parent;

        if(parent != null) {
            parent.subServices.put(id, this);
        }
    }
}
