import 'dart:convert';
import 'dart:typed_data';

import 'package:argon2/argon2.dart';
import 'package:meta/meta.dart';

/// Argon2id key derivation matching the UNET server configuration.
///
/// Parameters (must stay in sync with backend):
/// - algorithm : Argon2id
/// - timeCost  : 3 iterations
/// - memoryCost: 32 768 KiB (32 MB)
/// - parallelism: 1
/// - hashLength: 32 bytes
/// - version   : 0x13 (v1.3)
class KeyDerivation {
  static const int argon2TimeCost = 3;
  static const int argon2MemoryKb = 32768;
  static const int argon2Parallelism = 1;
  static const int argon2HashLength = 32;
  static const int minSaltBytes = 16;

  @visibleForTesting
  static bool allowInsecureParametersForTesting = false;

  /// Derive a 32-byte seed from [password] and hex-encoded [saltHex].
  ///
  /// Runs synchronously via `Argon2BytesGenerator`. Callers should off-load
  /// to `compute()` / `Isolate.run()` when running on the UI thread.
  static Uint8List deriveKey({
    required String password,
    required String saltHex,
    int? customTimeCost,
    int? customMemoryKb,
  }) {
    final saltBytes = _hexDecode(saltHex);
    _validateKdfParameters(
      customTimeCost: customTimeCost,
      customMemoryKb: customMemoryKb,
    );
    final params = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      saltBytes,
      iterations: customTimeCost ?? argon2TimeCost,
      memory: customMemoryKb ?? argon2MemoryKb,
      lanes: argon2Parallelism,
      version: Argon2Parameters.ARGON2_VERSION_13,
    );

    final generator = Argon2BytesGenerator()..init(params);
    final output = Uint8List(argon2HashLength);
    generator.generateBytes(Uint8List.fromList(utf8.encode(password)), output);
    return output;
  }

  static void _validateKdfParameters({
    required int? customTimeCost,
    required int? customMemoryKb,
  }) {
    // Production callers may raise cost, but may not lower the audited baseline.
    if (allowInsecureParametersForTesting) return;
    if (customTimeCost != null && customTimeCost < argon2TimeCost) {
      throw ArgumentError('invalid KDF parameters');
    }
    if (customMemoryKb != null && customMemoryKb < argon2MemoryKb) {
      throw ArgumentError('invalid KDF parameters');
    }
  }

  static Uint8List _hexDecode(String hexStr) {
    // Validate salts before decoding so malformed or weak salts fail uniformly.
    if (hexStr.isEmpty ||
        hexStr.length.isOdd ||
        hexStr.length ~/ 2 < minSaltBytes ||
        !RegExp(r'^[0-9a-fA-F]+$').hasMatch(hexStr)) {
      throw ArgumentError('invalid saltHex');
    }
    final result = <int>[];
    for (var i = 0; i < hexStr.length; i += 2) {
      result.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(result);
  }
}
