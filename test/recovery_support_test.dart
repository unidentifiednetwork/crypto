@TestOn('linux || mac-os || windows')
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart' as sodium_pkg;
import 'package:sodium/sodium_sumo.dart';
import 'package:test/test.dart';
import 'package:unet_crypto/unet_crypto.dart';

void main() {
  late SodiumSumo sodium;

  setUpAll(() async {
    sodium = await sodium_pkg.SodiumSumoInit.init(_openLibsodium);
  });

  test('SignedPayload builds deterministic sorted payloads', () {
    final left = SignedPayload.build({
      'z': 'last',
      'a': 1,
      'skip': null,
      'm': true,
    });
    final right = SignedPayload.build({'m': true, 'a': 1, 'z': 'last'});

    expect(left, right);
    expect(
      utf8.decode(base64Url.decode(base64Url.normalize(left))),
      '{"a":1,"m":true,"z":"last"}',
    );
  });

  test('RecoveryPinCrypto rejects pins shorter than the package minimum', () {
    expect(
      () => RecoveryPinCrypto.derivePinKey(
        pin: '123',
        saltHex: '00112233445566778899aabbccddeeff',
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('RecoveryPinCrypto round-trips encrypted auth seeds', () {
    final pinKey = RecoveryPinCrypto.derivePinKey(
      pin: '1234',
      saltHex: '00112233445566778899aabbccddeeff',
    );
    final authSeed = Uint8List.fromList(
      List<int>.generate(32, (index) => index),
    );

    try {
      final blob = RecoveryPinCrypto.encryptSeedWithPinKey(
        sodium: sodium,
        authSeed: authSeed,
        pinKey: pinKey,
      );
      final decrypted = RecoveryPinCrypto.decryptSeedFromBlob(
        sodium: sodium,
        blobBase64: blob,
        pinKey: pinKey,
      );

      expect(decrypted, authSeed);
    } finally {
      pinKey.fillRange(0, pinKey.length, 0);
    }
  });
}

DynamicLibrary _openLibsodium() {
  try {
    return DynamicLibrary.open('libsodium.so');
  } on ArgumentError {
    return DynamicLibrary.open('libsodium.so.23');
  }
}
