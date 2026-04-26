import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/hkdf.dart';

/// DM key derivation from the auth seed.
///
/// **v2 (current)** — HKDF-SHA-512:
///   1. `PRK = HKDF-Extract(salt = "unet-dm-e2e-salt-v2", IKM = authSeed)`
///   2. `dmSeed = HKDF-Expand(PRK, info = "unet-dm-e2e-key-v2", L = 32)`
///   3. `publicKey = Curve25519.scalarMultBase(dmSeed)`
///
/// The resulting Curve25519 (X25519) keypair is used for `crypto.box`
/// envelope encryption between two users.
class DMKeyDerivation {
  /// Derive a Curve25519 box keypair from the 32-byte auth seed using HKDF.
  ///
  /// Returns `(publicKey, secretKey)`.
  /// `secretKey` is a [SecureKey] — callers **must** call `dispose()` after use.
  static ({Uint8List publicKey, SecureKey secretKey}) deriveFromSeed({
    required SodiumSumo sodium,
    required Uint8List authSeed,
  }) {
    final dmSeed = Hkdf.deriveKey(
      ikm: authSeed,
      salt: Uint8List.fromList(utf8.encode('unet-dm-e2e-salt-v2')),
      info: Uint8List.fromList(utf8.encode('unet-dm-e2e-key-v2')),
      length: 32,
    );

    final secretKey = SecureKey.fromList(sodium, dmSeed);
    dmSeed.fillRange(0, dmSeed.length, 0);

    final dmPublicKey = sodium.crypto.scalarmult.base(n: secretKey);

    return (publicKey: Uint8List.fromList(dmPublicKey), secretKey: secretKey);
  }
}
