import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

class CryptoException implements Exception {
  final String message;

  const CryptoException(this.message);

  @override
  String toString() => 'CryptoException: $message';
}

class DMEnvelopeCrypto {
  static const int maxEnvelopeSizeBytes = 65536;
  static const int x25519PublicKeyBytes = 32;
  static const String envelopeAlgorithm = 'x25519-xsalsa20-poly1305';

  static Future<String> encryptEnvelope({
    required SodiumSumo sodium,
    required Map<String, dynamic> payload,
    required Uint8List senderPublicKey,
    required SecureKey senderSecretKey,
    required Uint8List recipientPublicKey,
  }) async {
    final nonce = sodium.randombytes.buf(sodium.crypto.box.nonceBytes);
    final plainText = Uint8List.fromList(utf8.encode(jsonEncode(payload)));
    final cipher = sodium.crypto.box.easy(
      message: plainText,
      nonce: nonce,
      publicKey: recipientPublicKey,
      secretKey: senderSecretKey,
    );

    final envelope = {
      'v': 1,
      'alg': envelopeAlgorithm,
      'senderPublicKey': base64Encode(senderPublicKey),
      'nonce': base64Encode(nonce),
      'ciphertext': base64Encode(cipher),
    };

    return base64Encode(utf8.encode(jsonEncode(envelope)));
  }

  static Map<String, dynamic>? decryptEnvelope({
    required SodiumSumo sodium,
    required String encryptedPayload,
    required SecureKey recipientSecretKey,
    required Uint8List expectedSenderPublicKey,
  }) {
    // Fail before decoding attacker-controlled envelopes that exceed the package limit.
    if (encryptedPayload.length > maxEnvelopeSizeBytes) {
      throw ArgumentError('invalid envelope');
    }
    if (expectedSenderPublicKey.length != x25519PublicKeyBytes) {
      throw ArgumentError('invalid public key');
    }
    try {
      final envelopeJson = utf8.decode(base64Decode(encryptedPayload));
      final envelope = jsonDecode(envelopeJson) as Map<String, dynamic>;
      if (envelope['v'] != 1) {
        return null;
      }
      if (envelope['alg'] != envelopeAlgorithm) {
        throw const CryptoException('unsupported envelope algorithm');
      }

      final senderPublicKey = base64Decode(
        envelope['senderPublicKey'] as String,
      );
      if (senderPublicKey.length != x25519PublicKeyBytes) {
        throw ArgumentError('invalid public key');
      }
      if (!_constantTimeEquals(senderPublicKey, expectedSenderPublicKey)) {
        return null;
      }

      final nonce = base64Decode(envelope['nonce'] as String);
      final cipher = base64Decode(envelope['ciphertext'] as String);
      if (nonce.length != sodium.crypto.box.nonceBytes) {
        return null;
      }
      if (cipher.length < sodium.crypto.box.macBytes) {
        return null;
      }
      final opened = sodium.crypto.box.openEasy(
        cipherText: cipher,
        nonce: nonce,
        publicKey: senderPublicKey,
        secretKey: recipientSecretKey,
      );
      return jsonDecode(utf8.decode(opened)) as Map<String, dynamic>;
    } on CryptoException {
      rethrow;
    } on ArgumentError {
      rethrow;
    } catch (_) {
      return null;
    }
  }

  /// Constant-time byte comparison.
  ///
  /// Always processes all bytes to avoid timing side-channels.
  /// Returns `true` only when both lists are identical.
  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
