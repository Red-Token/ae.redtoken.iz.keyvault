package ae.redtoken.util;

import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import se.h3.ca.Constants;
import se.h3.labs.ca.wallet.ch.us.sm.pgp.OpenPGPCertFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

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
        } catch (IOException | UnreadableWalletException e) {
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

    public static String validateBlockZoneId(String id) {
        String regexPattern = "^[a-z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-z0-9.-]+$";
        if (Pattern.matches(regexPattern, id))
            return id;

        throw new RuntimeException("Not valid id");
    }

    public static DeterministicSeed createSubSeed(DeterministicSeed seed, String string) {
        MessageDigest md = getMessageDigest();
        md.update(seed.getSeedBytes());
        md.update(string.getBytes());
//        return DeterministicSeed.ofEntropy(md.digest(), "");
        return new DeterministicSeed(md.digest(), "",0);
    }

    public static void main(String[] args) throws Exception {

        SecureRandom sr2 = new SecureRandom();

        List<String> wordList = MnemonicCode.INSTANCE.toMnemonic(sr2.generateSeed(32));

        String txt = "help bulk involve trash weird orphan maple school company grid monitor enough lecture swear rely unhappy corn pioneer hidden second aerobic gorilla hurry awful";

        wordList.forEach(s -> {
            System.out.printf(s + " ");
        });

        System.out.println();

        List<String> mnemonic = wordList;
        String password = "";

        MnemonicCode.INSTANCE.check(mnemonic);

//        DeterministicSeed ds = DeterministicSeed.ofMnemonic(txt, password);
        DeterministicSeed ds = new DeterministicSeed(txt, null, "", 0);

        //6568118928763075758
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] seedBytes = ds.getSeedBytes();
        System.out.println(Base64.getEncoder().encodeToString(seedBytes));
        sr.setSeed(seedBytes);
        System.out.println(sr.nextLong());


        byte[] digest = MessageDigest.getInstance("SHA-256").digest("pgp:rsa2048-sha256".getBytes());
        byte[] seed = ByteUtils.xor(digest, sr.generateSeed(digest.length));
        SecureRandom sr3 = SecureRandom.getInstance("SHA1PRNG");
        sr3.setSeed(seed);

        String email = "rene.malmgren@h3.se";

        Path usersPath = new File("/var/tmp/data").toPath().resolve(email);

        boolean mkdirs = usersPath.toFile().mkdirs();

        System.out.println(mkdirs);

        final Constants SERVICE_CONSTANTS = new Constants(2048, "RSA", "SHA256withRSA", "SHA-256");

        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance(SERVICE_CONSTANTS.getAsym());
        kpg.initialize(SERVICE_CONSTANTS.getKeysize(), sr3);

        KeyPair kp = kpg.genKeyPair();

        RSAPublicKey pk = (RSAPublicKey) kp.getPublic();

        System.out.println(pk.getPublicExponent());


        OpenPGPCertFactory openPGPCertFactory = new OpenPGPCertFactory(kp, usersPath);
        openPGPCertFactory.setName("Rene Malmgren");
        openPGPCertFactory.setEmail(email);
        openPGPCertFactory.setPwd("Qwerty");
        openPGPCertFactory.create();
        openPGPCertFactory.save();
    }
}