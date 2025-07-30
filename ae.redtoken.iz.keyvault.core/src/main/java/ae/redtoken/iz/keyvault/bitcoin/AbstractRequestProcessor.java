package ae.redtoken.iz.keyvault.bitcoin;

import ae.redtoken.iz.keyvault.bitcoin.keymaster.KeyMasterExecutor;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.AbstractLinkReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.AbstractLinkSender;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.RequestReceiver;
import ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem.ResponseSender;

abstract class AbstractRequestProcessor<R> implements Runnable {
    private final KeyMasterExecutor kmr;
    final RequestReceiver<R> rr;
    final ResponseSender<R> rs;

    public AbstractRequestProcessor(KeyMasterExecutor kmr, AbstractLinkReceiver<R> lr, AbstractLinkSender<R> ls) {
        this.kmr = kmr;
        this.rr = new RequestReceiver<>(lr);
        this.rs = new ResponseSender<>(ls);
    }

    @Override
    public void run() {
        while (true) {
            AbstractLinkReceiver.RouteInfo<R> ri = new AbstractLinkReceiver.RouteInfo<>();
            kmr.executor.execute(kmr.new RequestTask(rr.receive(ri), response -> {
                rs.sendMessage(response, ri.route);
            }));
        }
    }
}
