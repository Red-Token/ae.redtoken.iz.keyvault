package ae.redtoken.iz.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static ae.redtoken.util.Util.assertDirectoryExists;

public class TestPersist {

    static class Config<V extends X, T extends Container<V>> {
        Map<String,T> map = new HashMap<>();

        void persistAll() throws IOException {
            for (T t : map.values()) {
                t.persist(new File("/tmp/file.json"));
            }
        }
    }

    abstract public static class Container<T extends X> {
        T data;

        protected abstract Class<T> getTypeClass();

        Container(File file) throws IOException {
            load(file);
        }

        void persist(File file) throws IOException {
            ObjectMapper om = new ObjectMapper();
            assertDirectoryExists(file.getParentFile());
            om.writeValue(file, data);
        }

        void load(File file) throws IOException {
            ObjectMapper om = new ObjectMapper();
            this.data = om.readValue(file, getTypeClass());
        }
    }

    public static class X {
        public int x = 100;
    }

    static class Y extends X {
        public String y = "ysss";
    }

    @Test
    void testPersist() throws Exception {

        File file = new File("/tmp/testPersist.json");

        X x = new Y();

        ObjectMapper om = new ObjectMapper();
        assertDirectoryExists(file.getParentFile());
        om.writeValue(file, x);

        Y x2 = (Y) om.readValue(file, Y.class);


    }
}
