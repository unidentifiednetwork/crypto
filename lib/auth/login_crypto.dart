import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

/// Generic domain-separated Ed25519 challenge signing.
///
/// All UNET auth flows follow the same pattern:
///   1. Argon2id(password, salt) → 32-byte seed
///   2. Ed25519 keypair from seed
///   3. sign("{domain}:{payload}")
///
/// This class provides signing for **all** UNET auth operations:
/// - Login:           `unet-login-challenge:{challenge}`
/// - Registration:    `unet-register:{username}:{keySalt}`
/// - Recovery:        `unet-recovery-challenge:{challenge}`
/// - Account deletion:`unet-delete-account-challenge:{challenge}`
/// - Password change: `unet-change-password-challenge:{challenge}`
class LoginCrypto {
  /// Sign a login challenge.
  ///
  /// Domain-separation: `unet-login-challenge:{challenge}`
  static String signLoginChallenge({
    required SodiumSumo sodium,
    required Uint8List seed,
    required String challenge,
  }) {
    if (seed.length != 32) {
      throw ArgumentError('seed must be exactly 32 bytes, got ${seed.length}');
    }
    _validateChallenge(challenge);

    return _signDomain(
      sodium: sodium,
      seed: seed,
      domain: 'unet-login-challenge',
      payload: challenge,
    );
  }

  /// Low-level: sign `"{domain}:{payload}"` with Ed25519-from-seed.
  ///
  /// Exposed for domain strings not covered by the convenience methods.
  static String signDomainSeparated({
    required SodiumSumo sodium,
    required Uint8List seed,
    required String domain,
    required String payload,
  }) {
    _validateChallenge(payload);
    return _signDomain(
      sodium: sodium,
      seed: seed,
      domain: domain,
      payload: payload,
    );
  }

  /// Extract the Ed25519 **public key** bytes from a 32-byte seed.
  static Uint8List publicKeyFromSeed({
    required SodiumSumo sodium,
    required Uint8List seed,
  }) {
    final seedKey = SecureKey.fromList(sodium, seed);
    final keypair = sodium.crypto.sign.seedKeyPair(seedKey);
    seedKey.dispose();
    final pk = Uint8List.fromList(keypair.publicKey);
    keypair.secretKey.dispose();
    return pk;
  }

  // ── internals ──────────────────────────────────────────────────────────────

  static String _signDomain({
    required SodiumSumo sodium,
    required Uint8List seed,
    required String domain,
    required String payload,
  }) {
    final seedKey = SecureKey.fromList(sodium, seed);
    final keypair = sodium.crypto.sign.seedKeyPair(seedKey);
    seedKey.dispose();

    final message = Uint8List.fromList(utf8.encode('$domain:$payload'));
    final signature = sodium.crypto.sign.detached(
      message: message,
      secretKey: keypair.secretKey,
    );
    keypair.secretKey.dispose();
    return base64Encode(signature);
  }

  static void _validateChallenge(String challenge) {
    // Use one non-leaking error for all malformed challenges.
    if (challenge.isEmpty || challenge.length < 16 || challenge.length > 512) {
      throw ArgumentError('invalid challenge');
    }
    final allowedPattern = RegExp(r'^[A-Za-z0-9+/=_-]+$');
    if (!allowedPattern.hasMatch(challenge)) {
      throw ArgumentError('invalid challenge');
    }
  }
}
