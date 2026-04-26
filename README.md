# UNET Crypto

Cryptographic module for UNET providing secure user authentication, account recovery, and end-to-end encrypted direct messages. Zero networking, zero storage, zero UI — only cryptographic primitives.

## 🧩 Modules

### Common (`lib/common/`)

| Module | Description |
|--------|-------------|
| **`key_derivation.dart`** | Argon2id key derivation (t=3, m=32 MB, p=1, len=32) for converting passwords to cryptographic seeds |
| **`key_utils.dart`** | Utilities: Ed25519 public key → SPKI/PEM encoding, cryptographically-secure salt generation, recovery key formatting |
| **`hkdf.dart`** | HKDF (RFC 5869) using HMAC-SHA-512 for domain-separated key derivation |

### Authentication (`lib/auth/`)

| Module | Description |
|--------|-------------|
| **`login_crypto.dart`** | Domain-separated Ed25519 challenge signing for login (`unet-login-challenge:{challenge}`) and generic auth operations |
| **`account_crypto.dart`** | Account deletion (`unet-delete-account-challenge:{challenge}`) and password change (`unet-change-password-challenge:{challenge}`) |
| **`recovery_crypto.dart`** | Account recovery: recovery key generation, SecretBox encryption of auth seed, and recovery-complete flow |

### Registration (`lib/registration/`)

| Module | Description |
|--------|-------------|
| **`registration_crypto.dart`** | Ed25519 registration signing (`unet-register:{username}:{keySalt}`) with public key PEM generation |

### Direct Message E2E Encryption (`lib/dm/`)

| Module | Description |
|--------|-------------|
| **`dm_envelope_crypto.dart`** | X25519 + XSalsa20-Poly1305 envelope encryption/decryption for end-to-end encrypted messages |
| **`dm_key_derivation.dart`** | HKDF-SHA-512 derivation of Curve25519 (X25519) DM keypair from auth seed |
| **`dm_key_wrapping.dart`** | XSalsa20-Poly1305 wrapping of DM private keys for secure server-side backup |

## 🔐 How It Works

### Authentication

1. **Key Derivation**: `Argon2id(password, salt) → 32-byte seed` (t=3, m=32 MB, p=1, len=32)
2. **Key Generation**: Ed25519 keypair from seed
3. **Challenge Signing**: `sign("{domain}:{payload}")` with domain separation

**Domain separation strings** (must match backend):
- Login: `unet-login-challenge`
- Registration: `unet-register`
- Recovery: `unet-recovery-challenge`
- Account deletion: `unet-delete-account-challenge`
- Password change: `unet-change-password-challenge`

### Account Recovery

1. **Setup**: Generate random 32-byte recovery key → derive Ed25519 keypair → encrypt auth seed with recovery key (XSalsa20-Poly1305) → store on server
2. **Recovery**: Enter recovery key → derive Ed25519 keypair → sign recovery challenge → submit new auth keypair → re-encrypt seed with new recovery key

### DM E2E Encryption

1. **Key Derivation** (v2):
   ```
   PRK = HKDF-Extract(salt="unet-dm-e2e-salt-v2", IKM=authSeed)
   dmSeed = HKDF-Expand(PRK, info="unet-dm-e2e-key-v2", L=32)
   dmKeyPair = Curve25519.scalarMultBase(dmSeed)
   ```
2. **Key Wrapping** (v3):
   ```
   wrapKey = HKDF(ikm=authSeed, salt="unet-dm-wrap-salt-v3", info="unet-dm-key-wrap-v3", L=32)
   encryptedDmPrivateKey = base64(nonce || secretbox(dmPrivateKey, nonce, wrapKey))
   ```
   - The DM private key is encrypted **client-side** using XSalsa20-Poly1305 with a wrap-key derived from the auth seed
   - Server only stores the encrypted blob and never sees the wrap-key or plaintext private key
3. **Envelope Encryption**:
   - X25519 shared secret for each message
   - XSalsa20-Poly1305 (libsodium `crypto.box`) for authenticated encryption
   - Envelope includes version, algorithm, sender public key, nonce, and ciphertext

## 📚 Usage Examples

### Derive Seed and Sign Login Challenge

```dart
import 'package:unet_crypto/unet_crypto.dart';
import 'package:sodium_libs/sodium_libs_sumo.dart';

final sodium = await SodiumSumo.init();

// Derive 32-byte seed from password
final salt = KeyUtils.generateSaltHex();
final seed = KeyDerivation.deriveKey(
  password: 'user-password',
  saltHex: salt,
);

// Sign login challenge
final signature = LoginCrypto.signLoginChallenge(
  sodium: sodium,
  seed: seed,
  challenge: 'server-provided-challenge',
);
```

### Register New User

```dart
final bundle = RegistrationCrypto.deriveAndSign(
  sodium: sodium,
  username: 'alice',
  password: 'secure-password',
);

// Send to server:
// - bundle.keySaltHex
// - bundle.publicKeyPem
// - bundle.signatureBase64
```

### Encrypt a Direct Message

```dart
// Derive DM keypair from auth seed
final (publicKey, secretKey) = DMKeyDerivation.deriveFromSeed(
  sodium: sodium,
  authSeed: seed,
);

// Encrypt message for recipient
final envelope = await DMEnvelopeCrypto.encryptEnvelope(
  sodium: sodium,
  payload: {'text': 'Hello, world!'},
  senderPublicKey: publicKey,
  senderSecretKey: secretKey,
  recipientPublicKey: recipientPublicKey,
);

// Don't forget to dispose the secret key
secretKey.dispose();
```

### Account Recovery Setup

```dart
final recoveryKey = RecoveryCrypto.generateRecoveryKey();
final recoveryKeyFormatted = KeyUtils.formatRecoveryKey(recoveryKey);

final setupBundle = RecoveryCrypto.prepareRecoverySetup(
  sodium: sodium,
  authSeed: seed,
  recoveryKey: recoveryKey,
  keySalt: salt,
);

// Store recoveryKeyFormatted offline (show to user)
// Send to server:
// - setupBundle.recoveryPublicKeyPem
// - setupBundle.encryptedSeedBase64
```

## 🔧 Dependencies

```yaml
sodium_libs: 3.3.0   # libsodium (Ed25519, X25519, SecretBox, etc.)
argon2: ^1.0.1        # Argon2id password hashing
crypto: ^3.0.6        # SHA-512 for HKDF
convert: ^3.1.2       # Hex encoding/decoding
meta: ^1.17.0         # @visibleForTesting annotations
```

## ⚙️ Security Notes

- **Argon2id parameters**: t=3, m=32 MB, p=1 — must match server configuration. Memory cost set to 32 MB for compatibility with low-end mobile devices;
- **Domain separation**: Unique context strings prevent cross-operation key reuse
- **Secure key disposal**: Always call `dispose()` on `SecureKey` objects after use
- **Constant-time comparisons**: Public key comparisons prevent timing attacks
- **Input validation**: All inputs validated before cryptographic operations
- **No custom crypto**: Uses only well-vetted primitives from libsodium and Argon2id
