package ae.redtoken.iz.keyvault;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;



import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;


public class TestRandom {

    @SneakyThrows
    @Test
    void name() {

        byte[] seed = "Hello World!".getBytes();
        SecureRandom random = SecureRandom.getInstance("DRBG");
        random.setSeed(seed); // Deterministic output
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        System.out.println(random.nextLong());

    }

    public static class DeterministicSecureRandom extends SecureRandom {
        public DeterministicSecureRandom(byte[] seed) {
            super(new AESCTRDRBG(seed), null);
        }

        private static class AESCTRDRBG extends SecureRandomSpi {
            private static final int BLOCK_SIZE = 16; // AES block size
            private final Cipher cipher;
            private final byte[] key;
            private byte[] counter;

            public AESCTRDRBG(byte[] seed) {
                try {
                    this.key = Arrays.copyOf(seed, 32); // Ensure 256-bit key
                    this.counter = new byte[BLOCK_SIZE]; // Initial counter = 0
                    this.cipher = Cipher.getInstance("AES/ECB/NoPadding"); // AES-ECB for CTR mode
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            protected void engineSetSeed(byte[] seed) {
                // Reset counter and re-initialize with new seed
                System.arraycopy(seed, 0, key, 0, Math.min(seed.length, key.length));
                Arrays.fill(counter, (byte) 0);
            }

            @SneakyThrows
            @Override
            protected void engineNextBytes(byte[] bytes) {
                int offset = 0;
                while (offset < bytes.length) {
                    byte[] block = cipher.doFinal(counter);
                    int toCopy = Math.min(block.length, bytes.length - offset);
                    System.arraycopy(block, 0, bytes, offset, toCopy);
                    offset += toCopy;
                    incrementCounter();
                }
            }

            private void incrementCounter() {
                for (int i = counter.length - 1; i >= 0; i--) {
                    if (++counter[i] != 0) break;
                }
            }

            @Override
            protected byte[] engineGenerateSeed(int numBytes) {
                byte[] seed = new byte[numBytes];
                engineNextBytes(seed);
                return seed;
            }
        }

        public static void main(String[] args) {
            byte[] seed = "FixedSeedForTest".getBytes();
            SecureRandom drbg = new DeterministicSecureRandom(seed);

            byte[] randomBytes = new byte[16];
            drbg.nextBytes(randomBytes);

            System.out.println("Random Output: " + Arrays.toString(randomBytes));
        }

        /**
         *
         *  MastSeed  + "alice@atlanta.com"  -> IdSeed  +  "ssh"  -> ProtocolSeed -> Generering av nycklar.
         *
         *
         *
         *
         *
         *
         *
         */







    }




}
