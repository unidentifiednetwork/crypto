// UNET open-source crypto modules.
//
// Pure cryptographic operations for registration, authentication,
// account recovery, and end-to-end encrypted direct messages.
//
// No networking, no storage, no UI — only crypto primitives.

// ── Common utilities ──────────────────────────────────────────────────────────
export 'common/hkdf.dart';
export 'common/key_derivation.dart';
export 'common/key_utils.dart';
export 'common/signed_payload.dart';

// ── Auth ──────────────────────────────────────────────────────────────────────
export 'auth/login_crypto.dart';
export 'registration/registration_crypto.dart';
export 'auth/account_crypto.dart';
export 'auth/recovery_crypto.dart';
export 'auth/recovery_pin_crypto.dart';

// ── DM (end-to-end encryption) ────────────────────────────────────────────────
export 'dm/dm_envelope_crypto.dart';
export 'dm/dm_key_derivation.dart';
export 'dm/dm_key_wrapping.dart';
