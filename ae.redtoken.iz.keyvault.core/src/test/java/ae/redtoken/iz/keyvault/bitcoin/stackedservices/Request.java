package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

public record Request(Avatar<?> sender, int id, String[] address, String message) {
}
