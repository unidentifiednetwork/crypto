import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/key_derivation.dart';
import '../common/key_utils.dart';
import 'login_crypto.dart';

/// Crypto operations for account deletion and password change.
///
/// Both flows follow the generic domain-separated signing pattern.
class AccountCrypto {
  /// Sign an account-deletion challenge.
  ///
  /// Domain-separation: `unet-delete-account-challenge:{challenge}`
  static String signDeleteAccountChallenge({
    required SodiumSumo sodium,
    required Uint8List seed,
    required String challenge,
  }) {
    return LoginCrypto.signDomainSeparated(
      sodium: sodium,
      seed: seed,
      domain: 'unet-delete-account-challenge',
      payload: challenge,
    );
  }

  /// Sign a password-change challenge with the **old** seed.
  ///
  /// Domain-separation: `unet-change-password-challenge:{challenge}`
  static String signChangePasswordChallenge({
    required SodiumSumo sodium,
    required Uint8List oldSeed,
    required String challenge,
  }) {
    return LoginCrypto.signDomainSeparated(
      sodium: sodium,
      seed: oldSeed,
      domain: 'unet-change-password-challenge',
      payload: challenge,
    );
  }

  /// Full password-change crypto bundle.
  ///
  /// Returns the signature (from old seed) plus the new public key in PEM
  /// and the new salt. The caller then sends everything to the server.
  static PasswordChangeBundle preparePasswordChange({
    required SodiumSumo sodium,
    required Uint8List oldSeed,
    required String newPassword,
    required String challenge,
  }) {
    final signature = signChangePasswordChallenge(
      sodium: sodium,
      oldSeed: oldSeed,
      challenge: challenge,
    );

    final newSalt = KeyUtils.generateSaltHex();
    final newSeed = KeyDerivation.deriveKey(
      password: newPassword,
      saltHex: newSalt,
    );
    final newPk = LoginCrypto.publicKeyFromSeed(sodium: sodium, seed: newSeed);
    final newPem = KeyUtils.publicKeyToSpkiPem(newPk);

    final newSeedSecure = SecureKey.fromList(sodium, newSeed);
    newSeed.fillRange(0, newSeed.length, 0);

    return PasswordChangeBundle(
      signatureBase64: signature,
      newPublicKeyPem: newPem,
      newKeySalt: newSalt,
      newSeed: newSeedSecure,
    );
  }
}

/// Result of [AccountCrypto.preparePasswordChange].
class PasswordChangeBundle {
  final String signatureBase64;
  final String newPublicKeyPem;
  final String newKeySalt;
  final SecureKey newSeed;

  /// Callers **must** call `newSeed.dispose()` after use.
  PasswordChangeBundle({
    required this.signatureBase64,
    required this.newPublicKeyPem,
    required this.newKeySalt,
    required this.newSeed,
  });
}
