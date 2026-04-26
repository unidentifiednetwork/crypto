import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:meta/meta.dart';

/// HKDF (HMAC-based Key Derivation Function) per RFC 5869.
///
/// Uses HMAC-SHA-512 as the underlying PRF, producing up to 64 bytes per
/// expand step. For UNET key derivation we always output exactly 32 bytes.
class Hkdf {
  Hkdf._();

  /// Full HKDF: extract-then-expand.
  ///
  /// [ikm]  – input keying material (high-entropy, e.g. Argon2id seed)
  /// [salt] – optional salt (if null, defaults to HashLen zero bytes)
  /// [info] – context / domain-separation string
  /// [length] – desired output length in bytes (default 32)
  static Uint8List deriveKey({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    int length = 32,
  }) {
    return _deriveKey(
      ikm: ikm,
      salt: salt,
      info: info,
      length: length,
      hash: sha512,
    );
  }

  @visibleForTesting
  static Uint8List deriveKeyForTesting({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    int length = 32,
    required Hash hash,
  }) {
    // Test-only hook keeps production HKDF output unchanged while validating RFC vectors.
    return _deriveKey(
      ikm: ikm,
      salt: salt,
      info: info,
      length: length,
      hash: hash,
    );
  }

  static Uint8List _deriveKey({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    required int length,
    required Hash hash,
  }) {
    final hashLength = hash.convert(const <int>[]).bytes.length;
    final prk = _extract(
      salt: salt,
      ikm: ikm,
      hash: hash,
      hashLength: hashLength,
    );
    return _expand(
      prk: prk,
      info: info,
      length: length,
      hash: hash,
      hashLength: hashLength,
    );
  }

  /// HKDF-Extract: PRK = HMAC-SHA-512(salt, IKM)
  static Uint8List _extract({
    Uint8List? salt,
    required Uint8List ikm,
    required Hash hash,
    required int hashLength,
  }) {
    // Keep SHA-512 as the production default while allowing RFC SHA-256 vectors in tests.
    final effectiveSalt = salt ?? Uint8List(hashLength);
    final hmac = Hmac(hash, effectiveSalt);
    return Uint8List.fromList(hmac.convert(ikm).bytes);
  }

  /// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to [length] bytes
  /// where T(i) = HMAC-SHA-512(PRK, T(i-1) || info || i)
  static Uint8List _expand({
    required Uint8List prk,
    required Uint8List info,
    required int length,
    required Hash hash,
    required int hashLength,
  }) {
    if (length <= 0 || length > 255 * hashLength) {
      throw ArgumentError(
        'length must be between 1 and ${255 * hashLength}, got $length',
      );
    }

    final n = (length + hashLength - 1) ~/ hashLength;
    final okm = <int>[];
    var previous = Uint8List(0);

    for (var i = 1; i <= n; i++) {
      final hmac = Hmac(hash, prk);
      final input = Uint8List(previous.length + info.length + 1);
      input.setAll(0, previous);
      input.setAll(previous.length, info);
      input[input.length - 1] = i;
      previous = Uint8List.fromList(hmac.convert(input).bytes);
      okm.addAll(previous);
    }

    return Uint8List.fromList(okm.sublist(0, length));
  }
}
