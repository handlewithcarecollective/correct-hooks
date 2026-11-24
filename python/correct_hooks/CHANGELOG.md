# Changelog

All notable changes to the `correct_hooks` Python package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (24. November, 2026)

- **Added:** `correct_hooks.v2` module containing the v2 signature implementation.
- **Changed:** The package root now re-exports `correct_hooks.v2`, so `sign` and `Verifier` produce and verify v2 signatures.
- **Changed:** `sign` returns a single string that should be set as the `correct-hooks-signature` header. The `correct-hooks-signature-components` header is no longer used.
- **Changed:** `verify` no longer requires a `correct-hooks-signature-components` header value.
- **Changed:** The `recipient_id` and `target_url` pair has been replaced by a single `target_id`. `SignArgs`, `VerifierConfig`, and `VerifyArgs` are affected.
- **Changed:** The previous v1 signing and verification methods can be accessed through the `correct_hooks.v1` module. To keep signing and verifying v1 signatures, change imports from `correct_hooks` to `correct_hooks.v1`.
- **Changed:** To include both v1 and v2 signatures in a webhook request, call both sign methods, and concatenate the `correct-hooks-signature` values together separated by a space.

## 0.2.0 (12. November, 2026)

- **Added:** When loading public verifying key sets, verifiers now ignore keys that have unexpected fields (which could indicate manual manipulation of the key set and a potentially leaked secret).
