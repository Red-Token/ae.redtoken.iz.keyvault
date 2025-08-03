package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr;

import ae.redtoken.cf.sm.nostr.NostrExporter;
import ae.redtoken.iz.keyvault.bitcoin.ConfigurationHelper;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.AbstractConfigurationStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinConfiguration;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolMessages;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.BitcoinProtocolStackedService;
import ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin.IBitcoinConfigurationService;
import ae.redtoken.iz.keyvault.bitcoin.keyvault.KeyVaultProxy;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrCredentials;
import ae.redtoken.iz.keyvault.protocols.nostr.NostrMetaData;
import ae.redtoken.util.WalletHelper;
import lombok.SneakyThrows;
import nostr.base.PublicKey;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.*;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;
import java.util.stream.Collectors;

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
