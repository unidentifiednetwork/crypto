import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/key_derivation.dart';
import '../common/key_utils.dart';
import '../common/signed_payload.dart';
import 'login_crypto.dart';

/// Crypto operations for account recovery.
///
/// Recovery flow:
///   1. **Setup**: user stores a random 32-byte recovery key offline.
///      The auth seed is encrypted with that key via XSalsa20-Poly1305
///      (`crypto.secretBox`) and sent to the server along with the
///      recovery-derived Ed25519 public key.
///   2. **Recover**: user enters recovery key → derive Ed25519 pair →
///      sign recovery challenge → submit new auth keypair to server.
class RecoveryCrypto {
  /// Generate a random 32-byte recovery key.
  static Uint8List generateRecoveryKey() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
  }

  /// Create the recovery setup payload.
  ///
  /// Returns the encrypted seed (nonce ‖ ciphertext) and the
  /// recovery-derived Ed25519 public key PEM.
  static RecoverySetupBundle prepareRecoverySetup({
    required SodiumSumo sodium,
    required Uint8List authSeed,
    required Uint8List recoveryKey,
    required String keySalt,
  }) {
    // Derive Ed25519 pair from Argon2id(hex(recoveryKey), keySalt)
    final recoveryHex = hex.encode(recoveryKey);
    final recoverySeed = KeyDerivation.deriveKey(
      password: recoveryHex,
      saltHex: keySalt,
    );
    final pk = LoginCrypto.publicKeyFromSeed(
      sodium: sodium,
      seed: recoverySeed,
    );
    final publicKeyPem = KeyUtils.publicKeyToSpkiPem(pk);

    // Encrypt auth seed with recovery key via SecretBox
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final recoverySecret = SecureKey.fromList(sodium, recoveryKey);
    final Uint8List encrypted;
    try {
      encrypted = sodium.crypto.secretBox.easy(
        message: authSeed,
        nonce: nonce,
        key: recoverySecret,
      );
    } finally {
      recoverySecret.dispose();
    }
    final combined = Uint8List(nonce.length + encrypted.length)
      ..setAll(0, nonce)
      ..setAll(nonce.length, encrypted);

    return RecoverySetupBundle(
      recoveryPublicKeyPem: publicKeyPem,
      encryptedSeedBase64: base64.encode(combined),
    );
  }

  /// Sign a recovery challenge.
  ///
  /// Domain-separation: `unet-recovery-challenge:{challenge}`
  static String signRecoveryChallenge({
    required SodiumSumo sodium,
    required Uint8List recoverySeed,
    required String challenge,
  }) {
    return LoginCrypto.signDomainSeparated(
      sodium: sodium,
      seed: recoverySeed,
      domain: 'unet-recovery-challenge',
      payload: challenge,
    );
  }

  static String signRecoverySetupRequest({
    required SodiumSumo sodium,
    required Uint8List authSeed,
    required String recoveryPublicKey,
    required String recoveryData,
    required String recoveryKeySalt,
    required int recoveryKeyIterations,
  }) {
    return LoginCrypto.signDomainSeparated(
      sodium: sodium,
      seed: authSeed,
      domain: 'unet-recovery-setup',
      payload: SignedPayload.build({
        'recoveryData': recoveryData,
        'recoveryKeyIterations': recoveryKeyIterations,
        'recoveryKeySalt': recoveryKeySalt,
        'recoveryPublicKey': recoveryPublicKey,
      }),
    );
  }

  static String buildRecoveryCompletePayload({
    required String username,
    required String type,
    required String challenge,
    required String newPublicKey,
    required String newKeySalt,
    required int newKeyIterations,
    String? newRecoveryPublicKey,
    String? newRecoveryData,
    String? newRecoveryKeySalt,
    int? newRecoveryKeyIterations,
    String? newRecoveryPinBlob,
    String? newRecoveryPinSalt,
    String? newRecoveryPinPublicKey,
  }) {
    return SignedPayload.build({
      'challenge': challenge,
      'newKeyIterations': newKeyIterations,
      'newKeySalt': newKeySalt,
      'newPublicKey': newPublicKey,
      'newRecoveryData': newRecoveryData,
      'newRecoveryKeyIterations': newRecoveryKeyIterations,
      'newRecoveryKeySalt': newRecoveryKeySalt,
      'newRecoveryPinBlob': newRecoveryPinBlob,
      'newRecoveryPinPublicKey': newRecoveryPinPublicKey,
      'newRecoveryPinSalt': newRecoveryPinSalt,
      'newRecoveryPublicKey': newRecoveryPublicKey,
      'type': type,
      'username': username.trim().toLowerCase(),
    });
  }

  static String signRecoveryCompleteRequest({
    required SodiumSumo sodium,
    required Uint8List recoverySeed,
    required String payload,
  }) {
    return LoginCrypto.signDomainSeparated(
      sodium: sodium,
      seed: recoverySeed,
      domain: 'unet-recovery-complete',
      payload: payload,
    );
  }

  /// Prepare the full recovery-complete payload.
  ///
  /// Returns: recovery signature, new auth public key PEM, new recovery
  /// public key PEM, and the re-encrypted seed.
  static RecoveryCompleteBundle prepareRecoveryComplete({
    required SodiumSumo sodium,
    required String username,
    required Uint8List recoveryKeyBytes,
    required String newPassword,
    required String challenge,
    required String keySalt,
  }) {
    // 1. Derive recovery seed → sign challenge
    final recoveryHex = hex.encode(recoveryKeyBytes);
    final recoverySeed = KeyDerivation.deriveKey(
      password: recoveryHex,
      saltHex: keySalt,
    );

    // 2. New auth keypair from new password
    final newSalt = KeyUtils.generateSaltHex();
    final newSeed = KeyDerivation.deriveKey(
      password: newPassword,
      saltHex: newSalt,
    );
    final newAuthPk = LoginCrypto.publicKeyFromSeed(
      sodium: sodium,
      seed: newSeed,
    );
    final newAuthPem = KeyUtils.publicKeyToSpkiPem(newAuthPk);

    // 3. New recovery keypair (re-derive with new salt)
    final newRecoverySeed = KeyDerivation.deriveKey(
      password: recoveryHex,
      saltHex: newSalt,
    );
    final newRecoveryPk = LoginCrypto.publicKeyFromSeed(
      sodium: sodium,
      seed: newRecoverySeed,
    );
    final newRecoveryPem = KeyUtils.publicKeyToSpkiPem(newRecoveryPk);

    // 4. Encrypt new auth seed with recovery key
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final recoverySecret = SecureKey.fromList(sodium, recoveryKeyBytes);
    final Uint8List encrypted;
    try {
      encrypted = sodium.crypto.secretBox.easy(
        message: newSeed,
        nonce: nonce,
        key: recoverySecret,
      );
    } finally {
      recoverySecret.dispose();
    }
    final combined = Uint8List(nonce.length + encrypted.length)
      ..setRange(0, nonce.length, nonce)
      ..setRange(nonce.length, nonce.length + encrypted.length, encrypted);
    final newRecoveryData = base64.encode(combined);
    final recoveryPayload = buildRecoveryCompletePayload(
      username: username,
      type: 'key',
      challenge: challenge,
      newPublicKey: newAuthPem,
      newKeySalt: newSalt,
      newKeyIterations: KeyDerivation.argon2TimeCost,
      newRecoveryPublicKey: newRecoveryPem,
      newRecoveryData: newRecoveryData,
      newRecoveryKeySalt: newSalt,
    );
    final recoverySignature = signRecoveryCompleteRequest(
      sodium: sodium,
      recoverySeed: recoverySeed,
      payload: recoveryPayload,
    );
    recoverySeed.fillRange(0, recoverySeed.length, 0);

    final newSeedSecure = SecureKey.fromList(sodium, newSeed);
    newSeed.fillRange(0, newSeed.length, 0);

    return RecoveryCompleteBundle(
      recoverySignatureBase64: recoverySignature,
      newPublicKeyPem: newAuthPem,
      newKeySalt: newSalt,
      newRecoveryPublicKeyPem: newRecoveryPem,
      newRecoveryDataBase64: newRecoveryData,
      newSeed: newSeedSecure,
    );
  }
}

/// Result of [RecoveryCrypto.prepareRecoverySetup].
class RecoverySetupBundle {
  final String recoveryPublicKeyPem;
  final String encryptedSeedBase64;

  const RecoverySetupBundle({
    required this.recoveryPublicKeyPem,
    required this.encryptedSeedBase64,
  });
}

/// Result of [RecoveryCrypto.prepareRecoveryComplete].
class RecoveryCompleteBundle {
  final String recoverySignatureBase64;
  final String newPublicKeyPem;
  final String newKeySalt;
  final String newRecoveryPublicKeyPem;
  final String newRecoveryDataBase64;
  final SecureKey newSeed;

  /// Callers **must** call `newSeed.dispose()` after use.
  RecoveryCompleteBundle({
    required this.recoverySignatureBase64,
    required this.newPublicKeyPem,
    required this.newKeySalt,
    required this.newRecoveryPublicKeyPem,
    required this.newRecoveryDataBase64,
    required this.newSeed,
  });
}
