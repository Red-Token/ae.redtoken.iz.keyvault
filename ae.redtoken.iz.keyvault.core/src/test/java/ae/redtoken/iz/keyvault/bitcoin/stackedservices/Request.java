package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

public record Request(AbstractRunnable sender, int id, String[] address, String message) {
}
