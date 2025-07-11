package ae.redtoken.iz.keyvault.bitcoinstats;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Currency;
import java.util.Date;
import java.util.Map;

public class DailyExchangeRateList {
    static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    public static DailyExchangeRateList loadFromFile(File file) {
        try {
            return new ObjectMapper().readValue(file, DailyExchangeRateList.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private final String baseCurrency = "SEK";

    public Map<String, Map<String, Double>> rates;

    //TODO add HelperUtilHere
    private double getToRate(Date date, int currency) {
        return getToRate(date, Currency.getAvailableCurrencies().stream()
                .filter(c -> c.getNumericCode() == currency)
                .findFirst().orElseThrow(RuntimeException::new));
    }

    private double getToRate(Date date, Currency currency) {
        return getToRate(date, currency.getCurrencyCode());
    }

    private double getToRate(LocalDate date, Currency currency) {
        return getToRate(date.format(DateTimeFormatter.ISO_DATE), currency.getCurrencyCode());
    }

    private double getToRate(Date date, String currency) {
        return getToRate(sdf.format(date), currency);
    }

    private double getToRate(String date, String currency) {
        return currency == null || currency.equals(baseCurrency) ? 1.0 : rates.get(date).get(currency);
    }

    public double getFromRate(LocalDate date, Currency currency) {
        return 1 / getToRate(date, currency);
    }
    public double getFromRate(Date date, int currency) {
        return 1 / getToRate(date, currency);
    }

    public double getFromRate(Date date, Currency currency) {
        return 1 / getToRate(date, currency);
    }

    public double getFromRate(Date date, String currency) {
        return 1 / getToRate(date, currency);
    }

    public double getFromRate(String date, String currency) {
        return 1 / getToRate(date, currency);
    }
}
