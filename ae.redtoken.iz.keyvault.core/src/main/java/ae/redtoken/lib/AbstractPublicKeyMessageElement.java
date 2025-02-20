package ae.redtoken.lib;

import org.blkzn.msg.MessagePrimitiveTypes.uint16_t;
import org.blkzn.msg.MessagePrimitiveTypes.uint8_t;
import org.blkzn.msg.elements.ComplexMessageElement;

public class AbstractPublicKeyMessageElement extends ComplexMessageElement {
    public uint16_t ks;         // KeySize
    public uint8_t ka;          // KeyAlgoritm
    public uint16_t hs;         // HashSize
    public uint8_t ha;          // HashAlgoritm

    public int getKs() {
        return ks.getIntValue();
    }

    public int getKa() {
        return ka.getIntValue();
    }

    public int getHs() {
        return hs.getIntValue();
    }

    public int getHa() {
        return ha.getIntValue();
    }
}
