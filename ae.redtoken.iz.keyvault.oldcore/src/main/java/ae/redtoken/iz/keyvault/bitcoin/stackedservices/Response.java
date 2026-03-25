package ae.redtoken.iz.keyvault.bitcoin.stackedservices;

import java.util.Objects;

public final class Response {
    public long id;
    public String resp;

    public Response(long id, String resp) {
        this.id = id;
        this.resp = resp;
    }

    public Response() {
    }

    public long id() {
        return id;
    }

    public String resp() {
        return resp;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Response) obj;
        return this.id == that.id &&
                Objects.equals(this.resp, that.resp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, resp);
    }

    @Override
    public String toString() {
        return "Response[" +
                "id=" + id + ", " +
                "resp=" + resp + ']';
    }

}
