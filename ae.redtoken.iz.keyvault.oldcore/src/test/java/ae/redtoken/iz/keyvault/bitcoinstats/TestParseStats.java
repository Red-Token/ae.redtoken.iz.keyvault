package ae.redtoken.iz.keyvault.bitcoinstats;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class TestParseStats {

    @Test
    void testRead() {

        ObjectMapper om = new ObjectMapper();
        try {
            DailyExchangeRateList list = om.readValue(new File("/tmp/test.json"), DailyExchangeRateList.class);

            System.out.println(list.toString());

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @SneakyThrows
    @Test
    void testParseStats() {
        List<String> lines = Files.readAllLines(Paths.get("/var/tmp/rust-txt"), StandardCharsets.UTF_8);

        ObjectMapper om = new ObjectMapper();
        DailyExchangeRateList list = om.readValue(new File("/tmp/test.json"), DailyExchangeRateList.class);

        while (!lines.isEmpty()) {
            StringBuilder newLine = new StringBuilder();

            for (int i = 0; i < 19; i++) {
                String line = lines.removeFirst();
                String[] split = line.split(":", 2)[1].trim().split(" ");
                for (String s : split)
                    newLine.append(s.trim().replace("\u202F", "")).append(";");
            }

            String date = newLine.toString().split(";")[1];
            newLine.append(list.rates.containsKey(date) ? list.rates.get(date).get("USD") : 0);

            System.out.println(newLine);
        }


    }
}
