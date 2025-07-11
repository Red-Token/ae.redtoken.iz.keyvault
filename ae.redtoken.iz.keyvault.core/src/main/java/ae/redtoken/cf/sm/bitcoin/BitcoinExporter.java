package ae.redtoken.cf.sm.bitcoin;

import ae.redtoken.cf.AbstractExporter;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Objects;

public class BitcoinExporter extends AbstractExporter {

    private final DeterministicSeed seed;
    private final String email;

    public BitcoinExporter(DeterministicSeed seed, Path root, String email, boolean forceOverWrite) {
        super(root, forceOverWrite);
        this.seed = seed;
        this.email = email;
    }

    protected String getSeedFileName() {
        return String.format("%s.seed", email);
    }

    protected void exportSeed(OutputStream stream) throws IOException {
        stream.write(Objects.requireNonNull(this.seed.getMnemonicString()).getBytes(StandardCharsets.UTF_8));
        stream.flush();
    }

    public void exportSeed() {
        export(this::exportSeed, getSeedFileName());
    }
}
