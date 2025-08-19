package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import ae.redtoken.iz.keyvault.bitcoin.ConfigurationHelper;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;

public class NostrConfigurationStackedService extends AbstractConfigurationStackedService implements INostrConfigurationService {
    public final NostrConfiguration config;
    private final KeyVaultProxy.NostrProtocolExecutor executor;
//    private final KeyChainGroup wkcg;

    public NostrConfigurationStackedService(NostrProtocolStackedService parent, NostrConfiguration config) {
        super(parent, new String(WalletHelper.mangle(ConfigurationHelper.toJSON(config))));
        this.config = config;
        this.executor = parent.parent.proxy.new NostrProtocolExecutor(config);
    }

    @Override
    public NostrProtocolMessages.NostrDescribeMessageAccept describe() {
        return new NostrProtocolMessages.NostrDescribeMessageAccept(new String[]{"describe", "get_public_key", "sign_event"});
    }

    @SneakyThrows
    @Override
    public NostrProtocolMessages.NostrGetPublicKeyAccept getPublicKey() {
        String publicKey = executor.getPublicKey();
        return new NostrProtocolMessages.NostrGetPublicKeyAccept(publicKey);
    }

    @Override
    public NostrProtocolMessages.NostrSignEventAccept signEvent(NostrProtocolMessages.NostrSignEventRequest request) {
        String signature = executor.signEvent(request.event());
        return new NostrProtocolMessages.NostrSignEventAccept(signature);
    }

    @Override
    public NostrProtocolMessages.NostrNip44EncryptEventAccept nip44Encrypt(NostrProtocolMessages.NostrNip44EncryptRequest request) {
        String encryptedMessage = executor.nip44Encrypt(request.pubKey(), request.counterPartyPubkey(), request.message());
        return new NostrProtocolMessages.NostrNip44EncryptEventAccept(encryptedMessage);
    }

    @Override
    public NostrProtocolMessages.NostrNip44DecryptEventAccept nip44Decrypt(NostrProtocolMessages.NostrNip44DecryptRequest request) {
        String message = executor.nip44Decrypt(request.pubKey(), request.counterPartyPubkey(), request.encryptedMessage());
        return new NostrProtocolMessages.NostrNip44DecryptEventAccept(message);
    }

//    @Override
//    public BitcoinProtocolMessages.GetWatchingKeyAccept getWatchingKey() {
//        return new BitcoinProtocolMessages.GetWatchingKeyAccept(
//                executor.getWatchingKey(),
//                executor.config.scriptTypes(),
//                executor.config.network());
//    }
//
//    @Override
//    public BitcoinProtocolMessages.BitcoinTransactionSignatureAccept signTransaction(BitcoinProtocolMessages.BitcoinTransactionSignatureRequest request) {
//        Transaction transaction = Transaction.read(ByteBuffer.wrap(request.tx()));
//
//        // Convert the binary map into Objects
//        Map<Sha256Hash, Transaction> transactionMap = request.map().entrySet().stream().collect(Collectors.toUnmodifiableMap(
//                entry -> Sha256Hash.wrap(entry.getKey()),
//                entry -> Transaction.read(ByteBuffer.wrap(entry.getValue()))));
//
//        // Connect the inputs in the request to the outputs
//        transaction.getInputs().forEach(ti -> {
//            ti.connect(transactionMap.get(ti.getOutpoint().hash()).getOutput(ti.getOutpoint().index()));
//        });
//
//        // Prompts the user
//        System.out.println("transaction: " + transaction);
//
//        //Yey, we are
//        TransactionSigner.ProposedTransaction pt = new TransactionSigner.ProposedTransaction(transaction);
//        LocalTransactionSigner signer = new LocalTransactionSigner();
//        signer.signInputs(pt, new WrapedKeyBag());
//        return new BitcoinProtocolMessages.BitcoinTransactionSignatureAccept(transaction.serialize());
//    }
}
