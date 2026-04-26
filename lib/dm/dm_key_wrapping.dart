import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';

import '../common/hkdf.dart';

/// Wrapping / unwrapping of the local DM private key for server-side backup.
///
/// The server stores an opaque encrypted blob (`encryptedDmPrivateKey`) that
/// only the key owner can decrypt.  The encryption uses XSalsa20-Poly1305
/// (libsodium `secretbox`) with a wrap-key derived from the Argon2id auth
/// seed — the server never sees the wrap-key, only the ciphertext.
///
/// Current derivation — HKDF-SHA-512:
///   wrapKey = HKDF(ikm=authSeed, salt="unet-dm-wrap-salt-v3",
///                  info="unet-dm-key-wrap-v3", L=32)
///   blob    = base64( nonce[24] || secretbox(privateKey, nonce, wrapKey) )
///
/// Domain separation ensures the wrap-key is independent from both the
/// auth key-pair seed and the DM key-pair seed.
class DMKeyWrapping {
  DMKeyWrapping._();

  /// Derive the 32-byte wrap-key from the 32-byte Argon2id auth seed (v3, HKDF).
  static Uint8List deriveWrapKey(Uint8List authSeed) {
    return Hkdf.deriveKey(
      ikm: authSeed,
      salt: Uint8List.fromList(utf8.encode('unet-dm-wrap-salt-v3')),
      info: Uint8List.fromList(utf8.encode('unet-dm-key-wrap-v3')),
      length: 32,
    );
  }

  /// Encrypt [privateKey] and return a base64-encoded blob ready for upload.
  ///
  /// The blob format is: `base64( nonce[24] || ciphertext )`.
  static String encryptPrivateKey({
    required SodiumSumo sodium,
    required Uint8List privateKey,
    required Uint8List wrapKey,
  }) {
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final wrapKeySecure = SecureKey.fromList(sodium, wrapKey);
    final Uint8List ciphertext;
    try {
      ciphertext = sodium.crypto.secretBox.easy(
        message: privateKey,
        nonce: nonce,
        key: wrapKeySecure,
      );
    } finally {
      wrapKeySecure.dispose();
    }

    final blob = Uint8List(nonce.length + ciphertext.length);
    blob.setAll(0, nonce);
    blob.setAll(nonce.length, ciphertext);
    return base64Encode(blob);
  }

  /// Attempt to decrypt a blob previously produced by [encryptPrivateKey].
  ///
  /// Returns the 32-byte private key on success, or `null` if decryption fails
  /// (wrong wrap-key, corrupted data, unexpected key length).
  static Uint8List? decryptPrivateKey({
    required SodiumSumo sodium,
    required String encryptedBlob,
    required Uint8List wrapKey,
  }) {
    try {
      final blob = base64Decode(encryptedBlob);
      final nonceLen = sodium.crypto.secretBox.nonceBytes;
      // blob must be at least nonce + MAC
      if (blob.length <= nonceLen + sodium.crypto.secretBox.macBytes) {
        return null;
      }

      final nonce = Uint8List.fromList(blob.sublist(0, nonceLen));
      final ciphertext = Uint8List.fromList(blob.sublist(nonceLen));

      final wrapKeySecure = SecureKey.fromList(sodium, wrapKey);
      final Uint8List plaintext;
      try {
        plaintext = sodium.crypto.secretBox.openEasy(
          cipherText: ciphertext,
          nonce: nonce,
          key: wrapKeySecure,
        );
      } finally {
        wrapKeySecure.dispose();
      }

      // Sanity check: DM private key must be exactly 32 bytes
      if (plaintext.length != 32) return null;
      return Uint8List.fromList(plaintext);
    } catch (_) {
      return null;
    }
  }
}
