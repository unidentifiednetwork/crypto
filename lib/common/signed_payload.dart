import 'dart:collection';
import 'dart:convert';

/// Deterministic signed-payload encoding shared with the backend.
///
/// Values are encoded as sorted JSON and then base64url without padding so the
/// payload can be passed through the existing domain-separated Ed25519 signer.
class SignedPayload {
  SignedPayload._();

  static String build(Map<String, Object?> fields) {
    final sorted = SplayTreeMap<String, Object?>();
    for (final entry in fields.entries) {
      if (entry.value != null) {
        sorted[entry.key] = entry.value;
      }
    }

    final jsonBytes = utf8.encode(jsonEncode(sorted));
    return base64UrlEncode(jsonBytes).replaceAll('=', '');
  }
}
