package ae.redtoken.lib;

import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ChaCha20SecureRandom extends SecureRandom {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int NONCE_SIZE = 8; // 64-bit nonce
    private static final int BLOCK_SIZE = 64; // 512-bit block

    private final ChaChaEngine chaCha20Engine;
    private byte[] key;
    private byte[] nonce;
    private int counter;

    // Constructor: initialize key and nonce, setup ChaCha20 engine
    public ChaCha20SecureRandom(byte[] seed) {
        if (seed.length < KEY_SIZE) {
            throw new IllegalArgumentException("Seed must be at least " + KEY_SIZE + " bytes.");
        }

        // Set up the key and nonce
        key = new byte[KEY_SIZE];
        nonce = new byte[NONCE_SIZE];

        // Derive key and nonce from seed using SHA-256
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(seed, 0, seed.length);
        sha256.doFinal(key, 0);

        // Set the nonce (for simplicity, using a static nonce)
        System.arraycopy(seed, 0, nonce, 0, NONCE_SIZE);

        chaCha20Engine = new ChaChaEngine();
        chaCha20Engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        counter = 0;  // Initialize the counter (counter starts at 0)
    }

    // Override nextBytes() method to provide random bytes
    @Override
    public void nextBytes(byte[] bytes) {
        int offset = 0;
        while (offset < bytes.length) {
            // Generate a new 64-byte block from ChaCha20
            byte[] block = new byte[BLOCK_SIZE];
            chaCha20Engine.processBytes(block, 0, BLOCK_SIZE, block, 0);

            // Increment the counter for the next block
            nonce[7]++;  // Increment nonce (little endian 64-bit increment)
            if (nonce[7] == 0) {
                nonce[6]++;
            }

            int blockSize = Math.min(bytes.length - offset, BLOCK_SIZE);
            System.arraycopy(block, 0, bytes, offset, blockSize);
            offset += blockSize;
        }
    }

    // Testing the ChaCha20SecureRandom class
    public static void main(String[] args) {
        try {

            String seed2 = "parent skill hidden sponsor quality hurry idle alone worry bicycle proud reveal dumb glare evil mystery wood robot emotion clutch ice promote snow doll";

            DeterministicSeed ds = DeterministicSeed.ofMnemonic(seed2, "");

            byte[] seedBytes = ds.getSeedBytes();

            // Generate a random seed (you can use a fixed or secure random seed)
            byte[] seed = new byte[32]; // 256-bit seed
            SecureRandom.getInstanceStrong().nextBytes(seed); // Securely populate the seed

            // Instantiate ChaCha20SecureRandom
            ChaCha20SecureRandom csprng = new ChaCha20SecureRandom(seedBytes);

            // Generate 32 random bytes
            byte[] randomBytes = new byte[32];
            csprng.nextBytes(randomBytes);

            // Print out the generated random bytes
            System.out.print("Generated random bytes: ");
            for (byte b : randomBytes) {
                System.out.format("%02x", b);
            }
            System.out.println();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
