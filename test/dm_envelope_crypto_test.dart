import 'dart:ffi';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart';
import 'package:sodium/sodium_sumo.dart' as sodium_pkg;
import 'package:sodium/sodium_sumo.dart';
import 'package:test/test.dart';
import 'package:unet_crypto/unet_crypto.dart';

void main() {
  late SodiumSumo sodium;

  setUpAll(() async {
    // Package tests load libsodium directly because flutter_tester does not export sodium symbols.
    sodium = await sodium_pkg.SodiumSumoInit.init(_openLibsodium);
  });

  test('DM envelope round-trip decrypts successfully', () async {
    final senderSeed = KeyDerivation.deriveKey(
      password: 'sender-pass',
      saltHex: '00112233445566778899aabbccddeeff',
    );
    final recipientSeed = KeyDerivation.deriveKey(
      password: 'recipient-pass',
      saltHex: 'ffeeddccbbaa99887766554433221100',
    );
    final senderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: senderSeed,
    );
    final recipientKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: recipientSeed,
    );

    try {
      final encrypted = await DMEnvelopeCrypto.encryptEnvelope(
        sodium: sodium,
        payload: const {'kind': 'TEXT', 'body': 'hello'},
        senderPublicKey: senderKeys.publicKey,
        senderSecretKey: senderKeys.secretKey,
        recipientPublicKey: recipientKeys.publicKey,
      );

      final decrypted = DMEnvelopeCrypto.decryptEnvelope(
        sodium: sodium,
        encryptedPayload: encrypted,
        recipientSecretKey: recipientKeys.secretKey,
        expectedSenderPublicKey: senderKeys.publicKey,
      );

      expect(decrypted, isNotNull);
      expect(decrypted!['kind'], 'TEXT');
      expect(decrypted['body'], 'hello');
    } finally {
      senderKeys.secretKey.dispose();
      recipientKeys.secretKey.dispose();
    }
  });

  test('DM envelope rejects unexpected sender public key', () async {
    final senderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'sender-pass',
        saltHex: '11112222333344445555666677778888',
      ),
    );
    final recipientKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'recipient-pass',
        saltHex: '88887777666655554444333322221111',
      ),
    );
    final unexpectedSenderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'other-pass',
        saltHex: '1234567890abcdef1234567890abcdef',
      ),
    );

    try {
      final encrypted = await DMEnvelopeCrypto.encryptEnvelope(
        sodium: sodium,
        payload: const {'kind': 'TEXT', 'body': 'hello'},
        senderPublicKey: senderKeys.publicKey,
        senderSecretKey: senderKeys.secretKey,
        recipientPublicKey: recipientKeys.publicKey,
      );

      final decrypted = DMEnvelopeCrypto.decryptEnvelope(
        sodium: sodium,
        encryptedPayload: encrypted,
        recipientSecretKey: recipientKeys.secretKey,
        expectedSenderPublicKey: unexpectedSenderKeys.publicKey,
      );

      expect(decrypted, isNull);
    } finally {
      senderKeys.secretKey.dispose();
      recipientKeys.secretKey.dispose();
      unexpectedSenderKeys.secretKey.dispose();
    }
  });

  test('DM envelope rejects tampered ciphertext', () async {
    final senderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'sender-pass',
        saltHex: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      ),
    );
    final recipientKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'recipient-pass',
        saltHex: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      ),
    );

    try {
      final encrypted = await DMEnvelopeCrypto.encryptEnvelope(
        sodium: sodium,
        payload: const {'kind': 'TEXT', 'body': 'hello'},
        senderPublicKey: senderKeys.publicKey,
        senderSecretKey: senderKeys.secretKey,
        recipientPublicKey: recipientKeys.publicKey,
      );

      final envelope =
          jsonDecode(utf8.decode(base64Decode(encrypted)))
              as Map<String, dynamic>;
      final tamperedCiphertext = base64Decode(envelope['ciphertext'] as String);
      tamperedCiphertext[0] = tamperedCiphertext[0] ^ 0x01;
      envelope['ciphertext'] = base64Encode(tamperedCiphertext);
      final tamperedPayload = base64Encode(utf8.encode(jsonEncode(envelope)));

      final decrypted = DMEnvelopeCrypto.decryptEnvelope(
        sodium: sodium,
        encryptedPayload: tamperedPayload,
        recipientSecretKey: recipientKeys.secretKey,
        expectedSenderPublicKey: senderKeys.publicKey,
      );

      expect(decrypted, isNull);
    } finally {
      senderKeys.secretKey.dispose();
      recipientKeys.secretKey.dispose();
    }
  });

  test('Key derivation stays deterministic for identical inputs', () {
    const salt = 'abcdefabcdefabcdefabcdefabcdefab';
    final seedA1 = KeyDerivation.deriveKey(
      password: 'same-password',
      saltHex: salt,
    );
    final seedA2 = KeyDerivation.deriveKey(
      password: 'same-password',
      saltHex: salt,
    );
    final seedB = KeyDerivation.deriveKey(
      password: 'different-password',
      saltHex: salt,
    );

    expect(base64Encode(seedA1), base64Encode(seedA2));
    expect(base64Encode(seedA1), isNot(base64Encode(seedB)));

    final dmA1 = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: seedA1,
    );
    final dmA2 = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: seedA2,
    );

    try {
      expect(base64Encode(dmA1.publicKey), base64Encode(dmA2.publicKey));
      expect(
        base64Encode(dmA1.secretKey.extractBytes()),
        base64Encode(dmA2.secretKey.extractBytes()),
      );
    } finally {
      dmA1.secretKey.dispose();
      dmA2.secretKey.dispose();
    }
  });

  test('HKDF matches RFC 5869 SHA-256 test vectors', () {
    // SHA-256 vectors exercise the generic test hook without changing production SHA-512 output.
    final cases = [
      (
        ikm: _bytesFromHex('0b' * 22),
        salt: _bytesFromHex('000102030405060708090a0b0c'),
        info: _bytesFromHex('f0f1f2f3f4f5f6f7f8f9'),
        length: 42,
        okm:
            '3cb25f25faacd57a90434f64d0362f2a'
            '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
            '34007208d5b887185865',
      ),
      (
        ikm: _bytesFromHex(
          '000102030405060708090a0b0c0d0e0f'
          '101112131415161718191a1b1c1d1e1f'
          '202122232425262728292a2b2c2d2e2f'
          '303132333435363738393a3b3c3d3e3f'
          '404142434445464748494a4b4c4d4e4f',
        ),
        salt: _bytesFromHex(
          '606162636465666768696a6b6c6d6e6f'
          '707172737475767778797a7b7c7d7e7f'
          '808182838485868788898a8b8c8d8e8f'
          '909192939495969798999a9b9c9d9e9f'
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
        ),
        info: _bytesFromHex(
          'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
          'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
          'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
          'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
          'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
        ),
        length: 82,
        okm:
            'b11e398dc80327a1c8e7f78c596a4934'
            '4f012eda2d4efad8a050cc4c19afa97c'
            '59045a99cac7827271cb41c65e590e09'
            'da3275600c2f09b8367793a9aca3db71'
            'cc30c58179ec3e87c14c01d5c1f3434f'
            '1d87',
      ),
      (
        ikm: _bytesFromHex('0b' * 22),
        salt: Uint8List(0),
        info: Uint8List(0),
        length: 42,
        okm:
            '8da4e775a563c18f715f802a063c5a31'
            'b8a11f5c5ee1879ec3454e5f3c738d2d'
            '9d201395faa4b61a96c8',
      ),
    ];

    for (final vector in cases) {
      final okm = Hkdf.deriveKeyForTesting(
        ikm: vector.ikm,
        salt: vector.salt,
        info: vector.info,
        length: vector.length,
        hash: sha256,
      );
      expect(convert.hex.encode(okm), vector.okm);
    }
  });

  test('HKDF project domain vector stays deterministic', () {
    // This locks the current UNET DM domain separation strings without changing derivation logic.
    final okm = Hkdf.deriveKey(
      ikm: Uint8List.fromList(List<int>.generate(32, (i) => i)),
      salt: Uint8List.fromList(utf8.encode('unet-dm-e2e-salt-v2')),
      info: Uint8List.fromList(utf8.encode('unet-dm-e2e-key-v2')),
      length: 32,
    );

    expect(
      convert.hex.encode(okm),
      '52dd3092ebc22cea370c1546fd6445c6b88162e78e21f4bd53a62f6e3c644a9e',
    );
  });

  test('public key length validation rejects malformed keys', () {
    expect(
      () => KeyUtils.publicKeyToSpkiPem(Uint8List(31)),
      throwsA(isA<ArgumentError>()),
    );

    final recipientSecret = SecureKey.fromList(sodium, Uint8List(32));
    try {
      expect(
        () => DMEnvelopeCrypto.decryptEnvelope(
          sodium: sodium,
          encryptedPayload: '',
          recipientSecretKey: recipientSecret,
          expectedSenderPublicKey: Uint8List(31),
        ),
        throwsA(isA<ArgumentError>()),
      );

      final envelope = {
        'v': 1,
        'alg': DMEnvelopeCrypto.envelopeAlgorithm,
        'senderPublicKey': base64Encode(Uint8List(31)),
        'nonce': base64Encode(Uint8List(sodium.crypto.box.nonceBytes)),
        'ciphertext': base64Encode(Uint8List(sodium.crypto.box.macBytes)),
      };
      final encoded = base64Encode(utf8.encode(jsonEncode(envelope)));

      expect(
        () => DMEnvelopeCrypto.decryptEnvelope(
          sodium: sodium,
          encryptedPayload: encoded,
          recipientSecretKey: recipientSecret,
          expectedSenderPublicKey: Uint8List(32),
        ),
        throwsA(isA<ArgumentError>()),
      );
    } finally {
      recipientSecret.dispose();
    }
  });

  test('salt validation rejects malformed saltHex values', () {
    // Invalid salts fail before Argon2 is invoked.
    for (final saltHex in [
      '',
      'abc',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
      '00' * 15,
    ]) {
      expect(
        () => KeyDerivation.deriveKey(password: 'password', saltHex: saltHex),
        throwsA(isA<ArgumentError>()),
      );
    }
  });

  test('custom KDF parameters stay compatible with older server settings', () {
    const salt = '00112233445566778899aabbccddeeff';

    final weakerTimeCostSeed = KeyDerivation.deriveKey(
      password: 'password',
      saltHex: salt,
      customTimeCost: KeyDerivation.argon2TimeCost - 1,
    );
    final weakerMemorySeed = KeyDerivation.deriveKey(
      password: 'password',
      saltHex: salt,
      customMemoryKb: KeyDerivation.argon2MemoryKb - 1,
    );

    expect(weakerTimeCostSeed, hasLength(KeyDerivation.argon2HashLength));
    expect(weakerMemorySeed, hasLength(KeyDerivation.argon2HashLength));
    expect(weakerTimeCostSeed, isNot(equals(weakerMemorySeed)));
  });

  test('decryptEnvelope rejects oversized envelopes before decoding', () {
    final recipientSecret = SecureKey.fromList(sodium, Uint8List(32));
    try {
      expect(
        () => DMEnvelopeCrypto.decryptEnvelope(
          sodium: sodium,
          encryptedPayload: 'A' * (DMEnvelopeCrypto.maxEnvelopeSizeBytes + 1),
          recipientSecretKey: recipientSecret,
          expectedSenderPublicKey: Uint8List(32),
        ),
        throwsA(isA<ArgumentError>()),
      );
    } finally {
      recipientSecret.dispose();
    }
  });

  test('decryptEnvelope accepts 64KB raw payload', () async {
    final senderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'sender-pass',
        saltHex: '00112233445566778899aabbccddeeff',
      ),
    );
    final recipientKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'recipient-pass',
        saltHex: 'ffeeddccbbaa99887766554433221100',
      ),
    );

    try {
      // Create a ~64KB text payload.
      final largePayload = {'kind': 'TEXT', 'text': 'x' * 65500};

      final encrypted = await DMEnvelopeCrypto.encryptEnvelope(
        sodium: sodium,
        payload: largePayload,
        senderPublicKey: senderKeys.publicKey,
        senderSecretKey: senderKeys.secretKey,
        recipientPublicKey: recipientKeys.publicKey,
      );

      // Should not throw "invalid envelope" error.
      final decrypted = DMEnvelopeCrypto.decryptEnvelope(
        sodium: sodium,
        encryptedPayload: encrypted,
        recipientSecretKey: recipientKeys.secretKey,
        expectedSenderPublicKey: senderKeys.publicKey,
      );

      expect(decrypted, isNotNull);
      expect(decrypted!['kind'], 'TEXT');
      expect(decrypted['text'].length, 65500);
    } finally {
      senderKeys.secretKey.dispose();
      recipientKeys.secretKey.dispose();
    }
  });

  test('decryptEnvelope accepts large legacy voice payload', () async {
    final senderKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'sender-pass',
        saltHex: '0123456789abcdef0123456789abcdef',
      ),
    );
    final recipientKeys = DMKeyDerivation.deriveFromSeed(
      sodium: sodium,
      authSeed: KeyDerivation.deriveKey(
        password: 'recipient-pass',
        saltHex: 'fedcba9876543210fedcba9876543210',
      ),
    );

    try {
      final largeVoicePayload = {
        'kind': 'VOICE',
        'mimeType': 'audio/mp4',
        'durationMs': 60000,
        'trimStartMs': 0,
        'trimEndMs': 60000,
        'waveform': List<double>.filled(40, 0.5),
        // Simulates legacy inline base64 audio payload used by older clients.
        'audioBase64': 'A' * 700000,
      };

      final encrypted = await DMEnvelopeCrypto.encryptEnvelope(
        sodium: sodium,
        payload: largeVoicePayload,
        senderPublicKey: senderKeys.publicKey,
        senderSecretKey: senderKeys.secretKey,
        recipientPublicKey: recipientKeys.publicKey,
      );

      final decrypted = DMEnvelopeCrypto.decryptEnvelope(
        sodium: sodium,
        encryptedPayload: encrypted,
        recipientSecretKey: recipientKeys.secretKey,
        expectedSenderPublicKey: senderKeys.publicKey,
      );

      expect(decrypted, isNotNull);
      expect(decrypted!['kind'], 'VOICE');
      expect((decrypted['audioBase64'] as String).length, 700000);
    } finally {
      senderKeys.secretKey.dispose();
      recipientKeys.secretKey.dispose();
    }
  });

  test('decryptEnvelope rejects unsupported alg field', () {
    final recipientSecret = SecureKey.fromList(sodium, Uint8List(32));
    try {
      final envelope = {
        'v': 1,
        'alg': 'unsupported',
        'senderPublicKey': base64Encode(Uint8List(32)),
        'nonce': base64Encode(Uint8List(sodium.crypto.box.nonceBytes)),
        'ciphertext': base64Encode(Uint8List(sodium.crypto.box.macBytes)),
      };
      final encoded = base64Encode(utf8.encode(jsonEncode(envelope)));

      expect(
        () => DMEnvelopeCrypto.decryptEnvelope(
          sodium: sodium,
          encryptedPayload: encoded,
          recipientSecretKey: recipientSecret,
          expectedSenderPublicKey: Uint8List(32),
        ),
        throwsA(isA<CryptoException>()),
      );
    } finally {
      recipientSecret.dispose();
    }
  });

  test('challenge validation rejects empty and malformed challenges', () {
    final seed = Uint8List(32);

    expect(
      () => LoginCrypto.signLoginChallenge(
        sodium: sodium,
        seed: seed,
        challenge: '',
      ),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => LoginCrypto.signDomainSeparated(
        sodium: sodium,
        seed: seed,
        domain: 'unet-test-challenge',
        payload: 'malformed challenge!',
      ),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => AccountCrypto.signDeleteAccountChallenge(
        sodium: sodium,
        seed: seed,
        challenge: 'short',
      ),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => AccountCrypto.signChangePasswordChallenge(
        sodium: sodium,
        oldSeed: seed,
        challenge: 'short',
      ),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => RecoveryCrypto.signRecoveryChallenge(
        sodium: sodium,
        recoverySeed: seed,
        challenge: 'short',
      ),
      throwsA(isA<ArgumentError>()),
    );
  });
}

Uint8List _bytesFromHex(String value) =>
    Uint8List.fromList(convert.hex.decode(value));

DynamicLibrary _openLibsodium() {
  try {
    return DynamicLibrary.open('libsodium.so');
  } on ArgumentError {
    return DynamicLibrary.open('libsodium.so.23');
  }
}
