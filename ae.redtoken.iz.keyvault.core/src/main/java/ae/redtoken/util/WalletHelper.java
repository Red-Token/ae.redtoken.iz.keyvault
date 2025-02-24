package ae.redtoken.util;

import org.bitcoinj.wallet.DeterministicSeed;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class WalletHelper {

    public static DeterministicSeed generateDeterministicSeed(int bytes) {
        SecureRandom sr = new SecureRandom();
        return new DeterministicSeed(sr, bytes * 8, "");
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

    public static DeterministicSeed readMnemonicWordsFromFile(File file) {
        try {
            InputStream is = Files.newInputStream(file.toPath());
            String txt = new String(is.readAllBytes());
            is.close();

//            return DeterministicSeed.ofMnemonic(txt, "");
            return new DeterministicSeed(txt, null, "", 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecureRandom getDeterministicSecureRandomFromSeed(DeterministicSeed seed) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(seed.getSeedBytes());
            return sr;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static DeterministicSeed createSubSeed(DeterministicSeed seed, String string) {
        MessageDigest md = getMessageDigest();
        md.update(seed.getSeedBytes());
        md.update(string.getBytes());
//        return DeterministicSeed.ofEntropy(md.digest(), "");
        return new DeterministicSeed(md.digest(), "", 0);
    }
}