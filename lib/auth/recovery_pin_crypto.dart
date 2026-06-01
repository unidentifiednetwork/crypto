import 'dart:convert';
import 'dart:typed_data';

import 'package:argon2/argon2.dart';
import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/hkdf.dart';
import '../common/key_utils.dart';
import 'login_crypto.dart';

/// Cryptographic operations for PIN-based recovery.
///
/// PIN recovery flow:
///   Setup:
///     1. Client generates a random 16-byte hex salt.
///     2. Client derives a 32-byte wrapping key:
///        `Argon2id(pin, salt, t=4, m=65536, p=1)` — intentionally heavier
///        than the standard auth KDF (t=3, m=32768) to resist brute-force.
///     3. Client encrypts `auth_seed` with the wrapping key via
///        `crypto.secretBox` (XSalsa20-Poly1305):
///        `blob = base64(nonce ‖ ciphertext)`
///     4. Client sends `(blob, salt)` to the server.
///        The server never learns the PIN.
///
///   Recover:
///     1. Client fetches `(blob, salt)` from server (unauthenticated endpoint).
///     2. Client re-derives wrapping key from `Argon2id(pin, salt)`.
///     3. Client decrypts seed from blob — throws on wrong PIN.
///     4. Client proceeds with the standard recovery challenge-response using
///        the decrypted seed.
class RecoveryPinCrypto {
  // Argon2id parameters — heavier than the standard auth KDF to resist
  // offline brute-force on the stolen blob.
  static const int pinTimeCost = 4;
  static const int pinMemoryKb = 65536; // 64 MiB
  static const int pinParallelism = 1;
  static const int pinHashLength = 32;
  static const int pinMinLength = 4;
  static final Uint8List _pinSigningSalt = Uint8List.fromList(
    utf8.encode('unet-recovery-pin-signing-salt-v1'),
  );
  static final Uint8List _pinSigningInfo = Uint8List.fromList(
    utf8.encode('unet-recovery-pin-signing-key-v1'),
  );

  /// Generate a random 16-byte hex salt for PIN key derivation.
  static String generatePinSaltHex() => KeyUtils.generateSaltHex(bytes: 16);

  /// Derive a 32-byte wrapping key from [pin] and hex-encoded [saltHex].
  ///
  /// Runs synchronously via `Argon2BytesGenerator`. Callers **must** off-load
  /// to `Isolate.run()` / `compute()` when running on the UI thread.
  static Uint8List derivePinKey({
    required String pin,
    required String saltHex,
  }) {
    if (pin.length < pinMinLength) {
      throw ArgumentError('invalid pin');
    }
    final saltBytes = _hexDecode(saltHex);
    final params = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      saltBytes,
      iterations: pinTimeCost,
      memory: pinMemoryKb,
      lanes: pinParallelism,
      version: Argon2Parameters.ARGON2_VERSION_13,
    );
    final generator = Argon2BytesGenerator()..init(params);
    final output = Uint8List(pinHashLength);
    generator.generateBytes(Uint8List.fromList(utf8.encode(pin)), output);
    return output;
  }

  /// Encrypt [authSeed] with [pinKey] using libsodium secretBox.
  ///
  /// Returns base64(`nonce ‖ ciphertext`).
  static String encryptSeedWithPinKey({
    required SodiumSumo sodium,
    required Uint8List authSeed,
    required Uint8List pinKey,
  }) {
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final key = SecureKey.fromList(sodium, pinKey);
    final Uint8List encrypted;
    try {
      encrypted = sodium.crypto.secretBox.easy(
        message: authSeed,
        nonce: nonce,
        key: key,
      );
    } finally {
      key.dispose();
    }
    final combined = Uint8List(nonce.length + encrypted.length)
      ..setAll(0, nonce)
      ..setAll(nonce.length, encrypted);
    return base64.encode(combined);
  }

  /// Derive a separate Ed25519 signing seed from the PIN wrapping key.
  static Uint8List derivePinSigningSeed(Uint8List pinKey) {
    return Hkdf.deriveKey(
      ikm: pinKey,
      salt: _pinSigningSalt,
      info: _pinSigningInfo,
    );
  }

  static String pinPublicKeyPem({
    required SodiumSumo sodium,
    required Uint8List pinKey,
  }) {
    final signingSeed = derivePinSigningSeed(pinKey);
    try {
      final publicKey = LoginCrypto.publicKeyFromSeed(
        sodium: sodium,
        seed: signingSeed,
      );
      return KeyUtils.publicKeyToSpkiPem(publicKey);
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
    }
  }

  static String signRecoveryPayload({
    required SodiumSumo sodium,
    required Uint8List pinKey,
    required String payload,
  }) {
    final signingSeed = derivePinSigningSeed(pinKey);
    try {
      return LoginCrypto.signDomainSeparated(
        sodium: sodium,
        seed: signingSeed,
        domain: 'unet-recovery-complete',
        payload: payload,
      );
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
    }
  }

  /// Decrypt an [authSeed] from a base64 blob created by [encryptSeedWithPinKey].
  ///
  /// Throws [RecoveryPinDecryptException] if the PIN is wrong or the blob is
  /// corrupted.
  static Uint8List decryptSeedFromBlob({
    required SodiumSumo sodium,
    required String blobBase64,
    required Uint8List pinKey,
  }) {
    final combined = base64.decode(blobBase64);
    final nonceLen = sodium.crypto.secretBox.nonceBytes;
    if (combined.length <= nonceLen) {
      throw const RecoveryPinDecryptException('Invalid blob format');
    }
    final nonce = combined.sublist(0, nonceLen);
    final ciphertext = combined.sublist(nonceLen);
    final key = SecureKey.fromList(sodium, pinKey);
    try {
      return sodium.crypto.secretBox.openEasy(
        cipherText: ciphertext,
        nonce: nonce,
        key: key,
      );
    } on SodiumException {
      throw const RecoveryPinDecryptException(
        'Incorrect PIN or corrupted data',
      );
    } finally {
      key.dispose();
    }
  }

  static Uint8List _hexDecode(String hexStr) {
    if (hexStr.isEmpty ||
        hexStr.length.isOdd ||
        hexStr.length != 32 ||
        !RegExp(r'^[0-9a-fA-F]+$').hasMatch(hexStr)) {
      throw ArgumentError('Invalid saltHex');
    }
    final result = <int>[];
    for (var i = 0; i < hexStr.length; i += 2) {
      result.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(result);
  }
}

/// Thrown when decryption fails, typically due to an incorrect PIN.
class RecoveryPinDecryptException implements Exception {
  final String message;
  const RecoveryPinDecryptException(this.message);

  @override
  String toString() => 'RecoveryPinDecryptException: $message';
}
