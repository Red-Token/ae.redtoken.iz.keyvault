package ae.redtoken.iz.keyvault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLogMain {
    static Logger logger = LoggerFactory.getLogger(TestLogMain.class);

    public static void main(String[] args) {
        logger.trace("Trace Message!");
        logger.debug("Debug Message!");
        logger.info("Info Message!");
    }

}
