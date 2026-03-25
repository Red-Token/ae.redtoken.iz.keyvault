package ae.redtoken.iz.keyvault.bitcoin.keymaster.services.avatarctrl;

import java.util.Objects;

public class AvatarCtrlMessages {
    public static final class AvatarCtrlLoginRequest {
        private final String event;

        public AvatarCtrlLoginRequest(String event) {
            this.event = event;
        }

        public String event() {
            return event;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (AvatarCtrlLoginRequest) obj;
            return Objects.equals(this.event, that.event);
        }

        @Override
        public int hashCode() {
            return Objects.hash(event);
        }

        @Override
        public String toString() {
            return "AvatarCtrlLoginRequest[" +
                    "event=" + event + ']';
        }
    }

    public static final class AvatarCtrlLoginAccept {
        private final String[] result;

        public AvatarCtrlLoginAccept(String[] result) {
            this.result = result;
        }

        public String[] result() {
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (AvatarCtrlLoginAccept) obj;
            return Objects.equals(this.result, that.result);
        }

        @Override
        public int hashCode() {
            return Objects.hash(result);
        }

        @Override
        public String toString() {
            return "AvatarCtrlLoginAccept[" +
                    "result=" + result + ']';
        }
    }
}
