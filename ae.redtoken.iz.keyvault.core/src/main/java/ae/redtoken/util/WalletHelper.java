package ae.redtoken.util;

import ae.redtoken.lib.ChaCha20SecureRandom;
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class WalletHelper {
    private static final Logger log
            = LoggerFactory.getLogger(WalletHelper.class);

    static String HASH_ALG = "SHA-256";

    public static DeterministicSeed generateDeterministicSeed(int bytes, String passphrase) {
        SecureRandom sr = new SecureRandom();
//        return new DeterministicSeed(sr, bytes * 8, "");
        return DeterministicSeed.ofRandom(sr, bytes * 8, passphrase);
    }

    public static void writeMnemonicWordsToFile(DeterministicSeed ds, File file) {
        try {
            OutputStream os = new FileOutputStream(file);
            os.write(Objects.requireNonNull(ds.getMnemonicString()).getBytes(StandardCharsets.UTF_8));
            os.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static DeterministicSeed readMnemonicWordsFromFile(File file, String passphrase) {
        try {
            InputStream is = Files.newInputStream(file.toPath());
            String txt = new String(is.readAllBytes());
            is.close();

            //TODO: Why?
//            return DeterministicSeed.ofMnemonic(txt, "");
            return DeterministicSeed.ofMnemonic(txt,passphrase);
//            return new DeterministicSeed(txt, null, "", 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecureRandom getDeterministicSecureRandomFromSeed(DeterministicSeed seed) {
//            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] seedBytes = Objects.requireNonNull(seed.getSeedBytes());
        log.debug("seed: {}", seedBytes);
        return new ChaCha20SecureRandom(seedBytes);

    }

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALG);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static DeterministicSeed createSubSeed(DeterministicSeed seed, String string, String passphrase) {
        MessageDigest md = getMessageDigest();
        md.update(seed.getSeedBytes());
        md.update(string.getBytes());
        return DeterministicSeed.ofEntropy(md.digest(), passphrase);
    }
}