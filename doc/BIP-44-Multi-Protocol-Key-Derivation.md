if # BIP-44 Multi-Protocol Key Derivation

## Overview

This document describes a key derivation scheme for multi-protocol HSM/vault systems
built on BIP-32 hierarchical deterministic key derivation, using the existing BIP-44
path structure and SLIP-44 protocol registry.

The scheme supports multiple cryptographic protocols (Bitcoin, Nostr, SSH, X.509,
OpenPGP, etc.) from a single master seed, with algorithm isolation, key rotation,
and HSM/smart card compatibility.

---

## Path Structure

```
m / 44' / prot' / id' / alg' / role'
```

Five levels. Conforms to BIP-44 depth convention. Each level can be hardened or
non-hardened depending on the protocol's requirements.

| Level | Field | Description |
|-------|-------|-------------|
| 1 | `44'` | BIP-44 purpose (standard, already exists) |
| 2 | `prot'` | Protocol identifier from SLIP-44 registry |
| 3 | `id'` | Identity / account |
| 4 | `alg'` | Algorithm, variant, and CSPRNG (packed) |
| 5 | `role'` | Role and key rotation (packed) |

---

## Level 2: Protocol (`prot'`)

Registered in the existing SLIP-44 coin type registry. Non-coin protocols follow
the precedent set by Nostr (1237).

| Value | Protocol |
|-------|----------|
| `0` | Bitcoin |
| `1237` | Nostr |
| TBD | SSH |
| TBD | X.509 |
| TBD | OpenPGP |

New protocols are added via SLIP-44 pull request.

---

## Level 3: Identity (`id'`)

| Value | Meaning |
|-------|---------|
| `0` | Default identity (recommended for most users) |
| `hash(name)` | Named identity, hashed to 31 bits |

### Identity Hashing

For named identities, the identity string (e.g. `"alice@home.com"`) is hashed
using SHA-256, truncated to the lower 31 bits:

```
id = SHA-256("alice@home.com")[0..31] & 0x7FFFFFFF
```

This makes named identities optional. Most users use `id = 0`. Named identities
are available when multiple identities are needed under the same protocol.

---

## Level 4: Algorithm (`alg'`)

### Bit Layout (32 bits)

```
Bit 31                                                          Bit 0
+------+--------------------------+----------------+------------------+
|  H   |       alg (15 bits)     | variant (8 bits)|  csprng (8 bits) |
|      |       bits 30-16        | bits 15-8       |  bits 7-0        |
+------+--------------------------+----------------+------------------+
```

| Field | Bits | Range | Description |
|-------|------|-------|-------------|
| H | 31 | 0-1 | BIP-32 hardened flag |
| alg | 30-16 | 0-32767 | Algorithm identifier from published table |
| variant | 15-8 | 0-255 | Algorithm parameters (key size, curve) |
| csprng | 7-0 | 0-255 | CSPRNG type; `0` = none (use raw 32 bytes) |

### Algorithm Table

Published global table. Schnorr is assigned `0` so that Bitcoin and Nostr
(the most common use cases) produce all-zero `alg` fields in the default
configuration.

| Value | Algorithm |
|-------|-----------|
| 0 | Schnorr |
| 1 | Ed25519 |
| 2 | RSA |
| 3 | ECDSA |
| 4 | Ed448 |
| 5 | ML-DSA (Dilithium) |
| 6 | SLH-DSA (SPHINCS+) |
| 7 | ML-KEM (Kyber) |
| 8 | Falcon |
| ... | ... |

Each protocol specification defines which algorithms from this table are
supported. Not all algorithms are valid for all protocols.

### Variant Table

Per-algorithm table. Interpretation depends on the algorithm.

#### Schnorr

| Value | Curve |
|-------|-------|
| 0 | secp256k1 |

#### Ed25519

| Value | Meaning |
|-------|---------|
| 0 | Default (only option) |

#### RSA

The variant value encodes the key size divided by 256:

```
variant = key_size / 256
```

| Value | Key Size |
|-------|----------|
| 2 | 512 |
| 3 | 768 |
| 4 | 1024 |
| 8 | 2048 |
| 12 | 3072 |
| 16 | 4096 |
| 32 | 8192 |
| 64 | 16384 |

No lookup table needed. The key size is derived directly: `key_size = variant * 256`.

#### ECDSA

| Value | Curve |
|-------|-------|
| 0 | secp256k1 |
| 1 | P-256 (secp256r1) |
| 2 | P-384 (secp384r1) |
| 3 | P-521 (secp521r1) |
| 4 | Brainpool P256r1 |
| 5 | Brainpool P384r1 |
| 6 | Brainpool P512r1 |

#### Ed448

| Value | Meaning |
|-------|---------|
| 0 | Default (only option) |

#### ML-DSA (Dilithium)

| Value | Variant |
|-------|---------|
| 0 | ML-DSA-44 |
| 1 | ML-DSA-65 |
| 2 | ML-DSA-87 |

#### SLH-DSA (SPHINCS+)

| Value | Variant |
|-------|---------|
| 0 | SLH-DSA-128s (SHA2) |
| 1 | SLH-DSA-128f (SHA2) |
| 2 | SLH-DSA-192s (SHA2) |
| 3 | SLH-DSA-192f (SHA2) |
| 4 | SLH-DSA-256s (SHA2) |
| 5 | SLH-DSA-256f (SHA2) |
| 6 | SLH-DSA-128s (SHAKE) |
| 7 | SLH-DSA-128f (SHAKE) |
| 8 | SLH-DSA-192s (SHAKE) |
| 9 | SLH-DSA-192f (SHAKE) |
| 10 | SLH-DSA-256s (SHAKE) |
| 11 | SLH-DSA-256f (SHAKE) |

### CSPRNG Table

Published global table. Used when the algorithm requires more than 32 bytes of
entropy for key generation (e.g. RSA prime generation).

| Value | CSPRNG |
|-------|--------|
| 0 | None - use the 32 bytes from BIP-32 derivation as the key directly |
| 1 | ChaCha20 |
| 2 | AES-256-CTR |
| 3 | HMAC-DRBG |
| ... | ... |

Algorithms where the 32-byte BIP-32 output is the private key (Ed25519, ECDSA,
Schnorr) use `csprng = 0`. Algorithms that need a CSPRNG for key generation (RSA)
use `csprng = 1` or higher.

---

## Level 5: Role (`role'`)

### Bit Layout (32 bits)

```
Bit 31                                          Bit 0
+------+---------------------+--------------------------+
|  H   |    role (15 bits)  |    rotation (16 bits)     |
|      |    bits 30-16      |    bits 15-0              |
+------+---------------------+--------------------------+
```

| Field | Bits | Range | Description |
|-------|------|-------|-------------|
| H | 31 | 0-1 | BIP-32 hardened flag |
| role | 30-16 | 0-32767 | Key purpose/role from per-protocol table |
| rotation | 15-0 | 0-65535 | Key rotation index |

### Role Tables (per protocol)

#### SSH

| Value | Role |
|-------|------|
| 0 | User authentication |
| 1 | Host key |

#### X.509

| Value | Role |
|-------|------|
| 0 | CA signing |
| 1 | TLS server |
| 2 | TLS client |
| 3 | Code signing |
| 4 | S/MIME (email) |

#### Bitcoin

| Value | Role |
|-------|------|
| 0 | Receive |
| 1 | Change |

#### Nostr

| Value | Role |
|-------|------|
| 0 | Identity |
| 1 | Delegation |

### Rotation

The rotation field provides key rotation within the same role. Most users will
always use `rotation = 0`. If a key is compromised or needs to be replaced,
increment the rotation index to derive a new key without changing any other
part of the path.

---

## Leaf Output

The BIP-32 derivation at the final level produces 32 bytes. How these bytes
become a key depends on the `csprng` field:

| CSPRNG value | Behavior |
|-------------|----------|
| `0` (none) | The 32 bytes **are** the private key |
| `1+` (ChaCha20, etc.) | The 32 bytes **seed** the specified CSPRNG, which feeds a `KeyPairGenerator` |

### Direct key (csprng = 0)

Used by Ed25519, ECDSA, Schnorr, Ed448, and post-quantum algorithms. The 32
bytes from BIP-32 derivation are used as the private key directly (or as the
seed for algorithms with specific seed formats).

### CSPRNG-derived key (csprng >= 1)

Used by RSA and other algorithms that require more than 32 bytes of entropy.
The 32 bytes initialize the specified CSPRNG, producing a deterministic byte
stream that feeds the key pair generator.

```
BIP-32 leaf (32 bytes) --> CSPRNG --> KeyPairGenerator --> Key Pair
```

The same seed + same CSPRNG always produces the same key pair.

---

## Execution Model

The derivation path selects **which key**. Operations are specified separately:

```
result = vault.execute({
    keypath:  m / 44' / prot' / id' / alg' / role',
    function: "sign" | "encrypt" | "decrypt" | "getPublicKey" | ...,
    params:   { hash_algo, padding, sighash_type, ... },
    payload:  data
})
```

| Field | Description |
|-------|-------------|
| `keypath` | Selects the key (BIP-32 derivation path) |
| `function` | Operation to perform |
| `params` | Operation-specific parameters (hash algorithm, padding, etc.) |
| `payload` | Data to operate on |

Runtime parameters like hash algorithm (SHA-256 vs SHA-512), padding scheme
(PKCS#1 v1.5 vs PSS), and sighash types do not affect key derivation. They
are passed at execution time.

---

## Example Paths

### Nostr (default)

```
m / 44' / 1237' / 0' / 0' / 0'
                   |    |    |
                   |    |    +-- role=0 (identity), rotation=0
                   |    +------- alg=0 (Schnorr), variant=0 (secp256k1), csprng=0 (raw)
                   +------------ default identity
```

All zeros after the protocol. The simplest possible path.

### Bitcoin (default)

```
m / 44' / 0' / 0' / 0' / 0'
               |    |    |
               |    |    +-- role=0 (receive), rotation=0
               |    +------- alg=0 (Schnorr), variant=0 (secp256k1), csprng=0 (raw)
               +------------ default identity
```

Same as Nostr — only the protocol number differs.

### SSH Ed25519

```
m / 44' / XXXX' / 0' / 0x0001_00_00' / 0'
                   |     |     |    |     |
                   |     |     |    |     +-- role=0 (user auth), rotation=0
                   |     |     |    +-------- csprng=0 (raw key)
                   |     |     +------------- variant=0 (default)
                   |     +------------------- alg=1 (Ed25519)
                   +------------------------- default identity
```

### SSH RSA-4096

```
m / 44' / XXXX' / 0' / 0x0002_10_01' / 0'
                   |     |     |    |     |
                   |     |     |    |     +-- role=0 (user auth), rotation=0
                   |     |     |    +-------- csprng=1 (ChaCha20)
                   |     |     +------------- variant=16 (4096/256)
                   |     +------------------- alg=2 (RSA)
                   +------------------------- default identity
```

### X.509 CA Signing RSA-2048, rotated once

```
m / 44' / YYYY' / hash("corp.com")' / 0x0002_08_01' / 0x0000_0001'
                   |                    |     |    |     |         |
                   |                    |     |    |     |         +-- rotation=1
                   |                    |     |    |     +------------ role=0 (CA signing)
                   |                    |     |    +------------------ csprng=1 (ChaCha20)
                   |                    |     +----------------------- variant=8 (2048/256)
                   |                    +----------------------------- alg=2 (RSA)
                   +------------------------------------------------- named identity
```

---

## Comparison with Existing Standards

### NIP-06 (Nostr)

| | NIP-06 | This scheme |
|---|---|---|
| Path | `m/44'/1237'/0'/0/0` | `m/44'/1237'/0'/0'/0'` |
| Depth | 5 | 5 |
| SLIP-44 | 1237 (same) | 1237 (same) |
| Algorithm | Implicit | Explicit (Schnorr = 0) |
| Rotation | Bump account | Rotation field |
| Compatible | - | Different keys (hardened vs non-hardened) |

### BIP-44 (Bitcoin)

| | BIP-44 | This scheme |
|---|---|---|
| Path | `m/44'/0'/0'/0/0` | `m/44'/0'/0'/0'/0'` |
| Depth | 5 | 5 |
| SLIP-44 | 0 (same) | 0 (same) |
| Algorithm | Implicit | Explicit (Schnorr = 0) |
| Compatible | - | Different keys (hardened vs non-hardened) |

---

## Hardened vs Non-Hardened

Each protocol specification defines which levels use hardened derivation.
The hardened flag (bit 31) is independent of the packed data fields.

**Recommended defaults:**

| Protocol | prot | id | alg | role |
|----------|------|----|-----|------|
| Bitcoin | H | H | H | non-H (xpub derivation) |
| Nostr | H | H | H | H |
| SSH | H | H | H | H |
| X.509 | H | H | H | H |

Non-hardened levels enable xpub-based public key derivation without exposing
the private key. This is primarily useful for Bitcoin (watching wallets).
Most other protocols use all-hardened paths.

---

## Published Tables Summary

| Table | Scope | Maintained by | Size |
|-------|-------|---------------|------|
| Protocol | SLIP-44 registry | SatoshiLabs | Existing + new entries |
| Algorithm | Global | This specification | ~10 entries |
| Variant | Per algorithm | This specification | ~5-12 entries each |
| CSPRNG | Global | This specification | ~5 entries |
| Role | Per protocol | Per-protocol specification | ~2-5 entries each |
| Identity hash | Global | This specification | One algorithm (SHA-256) |

---

## Security Properties

1. **Deterministic** - same seed + same path = same key, every time
2. **Algorithm isolation** - different `alg` values derive from different branches
3. **Variant isolation** - different key sizes or curves derive different keys
4. **Role isolation** - different roles derive different keys
5. **Rotation isolation** - rotated keys are cryptographically independent
6. **No private key storage** - only path metadata is persisted; keys are regenerated on demand
7. **Single seed backup** - the master mnemonic recovers all keys for all protocols
8. **Forward derivation only** - child keys cannot reveal parent or sibling keys (hardened levels)
9. **HSM/smart card compatible** - fixed depth, numeric indices, small published tables

---

## Design Decisions

### Why BIP-44 depth (5 levels)?

Matches the established convention. No new BIP purpose number needed.
Existing tooling recognizes the structure. Each level has a clear purpose.

### Why packed bit fields?

Keeps the path at 5 levels while encoding algorithm, variant, CSPRNG, role,
and rotation. Without packing, these would require 8+ levels.

### Why published tables instead of hashing?

Ensures deterministic interoperability across implementations. No ambiguity
about string canonicalization. Auditable on constrained devices.

### Why CSPRNG in the path?

Two implementations using different CSPRNGs from the same seed would produce
different RSA keys. Making the CSPRNG part of the key identity ensures
reproducibility.

### Why RSA variant = key_size / 256?

All standard RSA key sizes are multiples of 256. Dividing by 256 fits any
practical key size into 8 bits without a lookup table.

### Why identity hashing is optional?

Most users have one identity per protocol. Forcing a hash computation for
the common case (`id = 0`) adds complexity without benefit.
