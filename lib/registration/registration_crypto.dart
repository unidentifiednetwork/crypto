import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/key_derivation.dart';
import '../common/key_utils.dart';

class RegistrationSignatureBundle {
  final String keySaltHex;
  final String publicKeyBase64;
  final String publicKeyPem;
  final String signatureBase64;

  const RegistrationSignatureBundle({
    required this.keySaltHex,
    required this.publicKeyBase64,
    required this.publicKeyPem,
    required this.signatureBase64,
  });
}

class RegistrationCrypto {
  /// Derive seed, create Ed25519 keypair, sign registration payload.
  ///
  /// Domain-separation string: `unet-register:{username}:{keySalt}`
  static RegistrationSignatureBundle signRegistration({
    required SodiumSumo sodium,
    required String username,
    required String keySaltHex,
    required Uint8List seed,
  }) {
    final normalizedUsername = username.trim().toLowerCase();
    final seedKey = SecureKey.fromList(sodium, seed);
    final keypair = sodium.crypto.sign.seedKeyPair(seedKey);
    seedKey.dispose();

    final payload = 'unet-register:$normalizedUsername:$keySaltHex';
    final signature = sodium.crypto.sign.detached(
      message: Uint8List.fromList(utf8.encode(payload)),
      secretKey: keypair.secretKey,
    );

    final publicKeyBase64 = base64Encode(keypair.publicKey);
    final publicKeyPem = KeyUtils.publicKeyToSpkiPem(keypair.publicKey);
    final signatureBase64 = base64Encode(signature);
    keypair.secretKey.dispose();

    return RegistrationSignatureBundle(
      keySaltHex: keySaltHex,
      publicKeyBase64: publicKeyBase64,
      publicKeyPem: publicKeyPem,
      signatureBase64: signatureBase64,
    );
  }

  /// Convenience: derive seed + sign in one call.
  static RegistrationSignatureBundle deriveAndSign({
    required SodiumSumo sodium,
    required String username,
    required String password,
    String? keySaltHex,
  }) {
    final salt = keySaltHex ?? KeyUtils.generateSaltHex();
    final seed = KeyDerivation.deriveKey(password: password, saltHex: salt);
    final result = signRegistration(
      sodium: sodium,
      username: username,
      keySaltHex: salt,
      seed: seed,
    );
    seed.fillRange(0, seed.length, 0);
    return result;
  }
}
