package ae.redtoken.iz.keyvault;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLog {
    static class TestLogger {
        private static final Logger logger = LoggerFactory.getLogger(TestLogger.class);

        void callMe() {
            logger.error("This is a trace message");
            logger.trace("This is a debug message");
        }
    }

    @Test
    void testLog() {
        TestLogger logger = new TestLogger();
        logger.callMe();
    }
}
