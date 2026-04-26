import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';

/// Shared key utility functions.
class KeyUtils {
  static const int ed25519PublicKeyBytes = 32;

  /// Generate a cryptographically-secure random hex salt.
  static String generateSaltHex({int bytes = 32}) {
    final random = Random.secure();
    final salt = Uint8List(bytes);
    for (var i = 0; i < bytes; i++) {
      salt[i] = random.nextInt(256);
    }
    return hex.encode(salt);
  }

  /// Wrap a raw 32-byte Ed25519 public key in SPKI/PEM encoding.
  ///
  /// The server expects this format for public key registration.
  static String publicKeyToSpkiPem(Uint8List publicKey) {
    // Reject malformed public keys before encoding them into trusted metadata.
    if (publicKey.length != ed25519PublicKeyBytes) {
      throw ArgumentError('invalid public key');
    }
    const prefix = <int>[
      0x30, 0x2a, // SEQUENCE (42 bytes)
      0x30, 0x05, // SEQUENCE (5 bytes)
      0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
      0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused bits)
    ];
    final combined = Uint8List(prefix.length + publicKey.length)
      ..setRange(0, prefix.length, prefix)
      ..setRange(prefix.length, prefix.length + publicKey.length, publicKey);
    final body = base64.encode(combined);
    return '-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----';
  }

  /// Format a 32-byte recovery key as a human-readable hex string
  /// with hyphen-separated groups of 4.
  static String formatRecoveryKey(Uint8List key) {
    return hex
        .encode(key)
        .toUpperCase()
        .replaceAllMapped(RegExp(r'.{1,4}'), (m) => '${m.group(0)}-')
        .replaceFirst(RegExp(r'-$'), '');
  }
}
