package ae.redtoken.iz.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

public class Util {
    private static final Logger log
            = LoggerFactory.getLogger(Util.class);

    static void assertDirectoryExists(File dir) {
        if (dir == null) throw new NullPointerException("Directory cannot be null");

        if (dir.exists() && !dir.isDirectory()) {
            throw new IllegalArgumentException("Directory exists and is not a directory: " + dir.getAbsolutePath());
        }

        if (dir.mkdirs()) {
            log.debug("Directory created: {}", dir.getAbsolutePath());
        }
    }

    static <T> T parsePersistentData(File file, Class<T> cls) {
        try {
            ObjectMapper om = new ObjectMapper();
            return om.readValue(file, cls);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
