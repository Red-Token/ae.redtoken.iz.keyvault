package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.Objects;

public final class Request {
    public int id;
    public String[] address;
    public String message;

    public Request(int id, String[] address, String message) {
        this.id = id;
        this.address = address;
        this.message = message;
    }

    public Request() {
    }

    public int id() {
        return id;
    }

    public String[] address() {
        return address;
    }

    public String message() {
        return message;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Request) obj;
        return this.id == that.id &&
                Objects.equals(this.address, that.address) &&
                Objects.equals(this.message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, address, message);
    }

    @Override
    public String toString() {
        return "Request[" +
                "id=" + id + ", " +
                "address=" + address + ", " +
                "message=" + message + ']';
    }

}
