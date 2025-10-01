package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh;

import java.util.Objects;

public class SshProtocolMessages {

    public static final class SshGetPublicKeyAccept {
        public String pubKey;

        public SshGetPublicKeyAccept(String pubKey) {
            this.pubKey = pubKey;
        }

        public SshGetPublicKeyAccept() {
        }

        public String pubKey() {
            return pubKey;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SshGetPublicKeyAccept) obj;
            return Objects.equals(this.pubKey, that.pubKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(pubKey);
        }

        @Override
        public String toString() {
            return "SshGetPublicKeyAccept[" +
                    "pubKey=" + pubKey + ']';
        }

        }

    public static final class SshSignEventRequest {
        public byte[] publicKey;
        public byte[] data;

        public SshSignEventRequest() {
        }

        public SshSignEventRequest(byte[] publicKey, byte[] data) {
            this.publicKey = publicKey;
            this.data = data;
        }

        public byte[] publicKey() {
            return publicKey;
        }

        public byte[] data() {
            return data;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SshSignEventRequest) obj;
            return Objects.equals(this.publicKey, that.publicKey) &&
                    Objects.equals(this.data, that.data);
        }

        @Override
        public int hashCode() {
            return Objects.hash(publicKey, data);
        }

        @Override
        public String toString() {
            return "SshSignEventRequest[" +
                    "publicKey=" + publicKey + ", " +
                    "data=" + data + ']';
        }

        }

    public static final class SshSignEventAccept {
        public boolean accepted;
        public byte[] signature;

        public SshSignEventAccept(boolean accepted, byte[] signature) {
            this.accepted = accepted;
            this.signature = signature;
        }

        public SshSignEventAccept() {
        }

        public byte[] signature() {
            return signature;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SshSignEventAccept) obj;
            return Objects.equals(this.signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(signature);
        }

        @Override
        public String toString() {
            return "SshSignEventAccept[" +
                    "signature=" + signature + ']';
        }

        }
}
