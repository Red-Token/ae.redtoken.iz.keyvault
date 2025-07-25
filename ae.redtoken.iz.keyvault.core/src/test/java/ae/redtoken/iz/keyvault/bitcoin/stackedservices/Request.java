package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

public record Request(AvatarRunnable<?> sender, int id, String[] address, String message) {
}
