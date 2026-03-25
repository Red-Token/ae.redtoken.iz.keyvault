package ae.redtoken.iz.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BIP-44 spec example paths with pinned hex output.
 * Uses the "all abandon" mnemonic. Golden hex values are regression guards —
 * if derivation logic changes, these break.
 */
class GoldenPathTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final int H = 0x80000000;
    private static final HexFormat HEX = HexFormat.of();

    private final Bip32KeyDerivator kd = new Bip32KeyDerivator(MNEMONIC);

    private String deriveHex(int... path) {
        return HEX.formatHex(kd.derive(path));
    }

    // ── Golden paths ───────────────────────────────────────────────────

    /** m/44'/1237'/0'/0'/0' — Nostr default identity, Schnorr, index 0 */
    @Test
    void nostrDefault() {
        String hex = deriveHex(44 | H, 1237 | H, 0 | H, 0 | H, 0 | H);
        assertEquals("4f2d32ade6250539bb989a7cffd1d5ec882d16864f502632b6d4f087591f0ee1", hex);
    }

    /** m/44'/0'/0'/0'/0' — Bitcoin default, Schnorr, receive */
    @Test
    void bitcoinDefault() {
        String hex = deriveHex(44 | H, 0 | H, 0 | H, 0 | H, 0 | H);
        assertEquals("9138aa040b219a14ef56d98c7c587b9bb02a02015c870cf9c2dbfc333a295be0", hex);
    }

    /** m/44'/0'/0'/0x00000001'/0' — Bitcoin change address */
    @Test
    void bitcoinChange() {
        String hex = deriveHex(44 | H, 0 | H, 0 | H, 0x00000001 | H, 0 | H);
        assertEquals("24ed19a7ca741bd91b3b16b2460565bf24b08820794b56e6f9bb6367a8806fee", hex);
    }

    /** m/44'/22'/0'/0x00010000'/0' — SSH Ed25519 user-auth */
    @Test
    void sshEd25519UserAuth() {
        String hex = deriveHex(44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H);
        assertEquals("1b90b48173f1915e5528518ff0dcf45d66f0b50b7b28a45b9be6003b79e40561", hex);
    }

    /** m/44'/22'/0'/0x00010001'/0' — SSH Ed25519 host-key */
    @Test
    void sshEd25519HostKey() {
        String hex = deriveHex(44 | H, 22 | H, 0 | H, 0x00010001 | H, 0 | H);
        assertEquals("b11780919c6f65f7757e795fe5e412305deedd2f6e2b2053af390b10684452a6", hex);
    }

    /** m/44'/22'/0'/0x00021000'/0x01000000' — SSH RSA-4096, HMAC-DRBG */
    @Test
    void sshRsa4096() {
        String hex = deriveHex(44 | H, 22 | H, 0 | H, 0x00021000 | H, 0x01000000 | H);
        assertEquals("5c00451403518914c4c59df6758e18236d252d4c54dfcc0f477c2e5499aa99c7", hex);
    }

    /** m/44'/509'/hash("corp.com")'/0x00020800'/0x01000001' — X.509 CA RSA-2048, rotated once */
    @Test
    void x509CaRsa2048Rotated() {
        int identity = Bip32KeyDerivator.mangle("corp.com");
        String hex = deriveHex(44 | H, 509 | H, identity | H, 0x00020800 | H, 0x01000001 | H);
        assertEquals("2fbdf5dd9e758350d6cc064b79797db890c492a3c0e883220355e53b31e8a4e1", hex);
    }

    /** m/44'/22'/mangle("alice@atlanta.com")'/0x00010000'/0' — SSH with named identity */
    @Test
    void sshNamedIdentity() {
        int identity = Bip32KeyDerivator.mangle("alice@atlanta.com");
        String hex = deriveHex(44 | H, 22 | H, identity | H, 0x00010000 | H, 0 | H);
        assertEquals("ddd90999592b690f636bc83b0f4673d4ee11b04f7217fa9930e19f552858c561", hex);
    }

    // ── Cross-protocol / role isolation ─────────────────────────────────

    /** Nostr default vs Bitcoin default → different keys */
    @Test
    void nostrDefaultVsBitcoinDefault() {
        byte[] nostr   = kd.derive(44 | H, 1237 | H, 0 | H, 0 | H, 0 | H);
        byte[] bitcoin = kd.derive(44 | H, 0 | H,    0 | H, 0 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(nostr, bitcoin),
                "Nostr and Bitcoin default paths must produce different keys");
    }

    /** SSH user-auth vs host-key (same identity, different role) → different keys */
    @Test
    void sshUserAuthVsHostKey() {
        byte[] userAuth = kd.derive(44 | H, 22 | H, 0 | H, 0x00010000 | H, 0 | H);
        byte[] hostKey  = kd.derive(44 | H, 22 | H, 0 | H, 0x00010001 | H, 0 | H);
        assertFalse(java.util.Arrays.equals(userAuth, hostKey),
                "SSH user-auth and host-key paths must produce different keys");
    }
}
