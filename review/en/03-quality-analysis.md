# Quality Analysis of the AES Implementation

Branch: `feat/share-file-encryption` (commit `26dc99e`), diff against `main`:
24 files, ~1,020 lines added. This analysis evaluates architecture, code quality,
robustness, tests and maintainability – cryptographic correctness is covered by the
separate security analysis (`02-security-analysis.md`).

## 1. Architecture and design – strengths

**Clean encapsulation.** The entire crypto logic lives in a single new
`EncryptionService` (218 lines) with a clear, small API (`deriveKey`, `wrapKey`/
`unwrapKey`, `encryptChunk`, `createDecryptionStream`, `getPlaintextSize`). Storage
providers and the share service merely consume it; no crypto code is scattered across the
codebase. Constants (`NONCE_LENGTH`, `CHUNK_OVERHEAD`, …) are defined centrally and
exported rather than duplicated (`local.service.ts` imports `CHUNK_OVERHEAD`).

**Symmetric integration into both storage providers.** Local and S3 follow the same
pattern (unwrap → encryptChunk → plaintext size on the last chunk). The signature of
`create(...)` was extended uniformly with `wrappedEncryptionKey?`.

**Foresighted pinning.** Two decisions show operational experience: the Argon2 parameters
are pinned against library default changes, and the chunk size is frozen per share
(`encryptionChunkSize`) because the config value can be changed by an admin. (That the
pinning is not carried through to the end in one place – see section 3.)

**Consistent feature disabling.** ZIP, preview, password change, ClamAV, pre-signed S3
operations: every incompatibility is enforced in the backend **and** hidden in the
frontend, each with its own i18n error message. Particularly nice: the cookie cleanup
(`clearShareTokenCookies`) removes the new `_enc` cookie together with the `_token`
cookie – an easy detail to miss.

**Comment quality.** The comments consistently explain the *why* ("Pinned explicitly:
relying on the library defaults would make existing shares undecryptable…", "Always store
the size of the file itself, not the size it takes up on disk"). That is exactly the kind
of comment that makes the difference in crypto code.

**Good error ergonomics in the frontend.** The dedicated error code
`share_encryption_key_required` is recognized in the upload retry path: open the password
modal, refresh the cookie, retry the same chunk. Parallel uploads share a single modal
via the `pendingRequest` singleton. The UI description text of the encryption checkbox
honestly communicates the consequences (no password change, no preview/ZIP).

## 2. Tests – gaps

On the positive side: the Newman system tests cover the happy path end to end (create →
upload → complete → token → download with content comparison) plus three negative cases
(no password, ZIP, password change).

Missing, however:

- **Unit tests for `EncryptionService`** – the service is pure logic without I/O and
  would be trivially testable. Especially
  `getPlaintextSize`/`getChunkCount`/`createDecryptionStream` have edge cases (empty
  file, exactly full chunks, last chunk = 1 byte) that a system test with a 76-byte file
  does not cover.
- **A multi-chunk scenario**: the system test uploads exactly one chunk. The entire
  stream re-chunking logic (transform/flush, `expectedChunkIndex` with overhead) never
  runs through its interesting path in tests.
- **Tampering tests**: no test that a corrupted/truncated ciphertext actually fails at
  download time – which is the central security promise of the AAD construction.
- **Missing/foreign cookie at download time** (the `share_encryption_key_required` path).
- **The S3 path**: understandable (system tests run locally), but the S3 integration
  remains untested.

## 3. Robustness – main finding

**Missing server-side validation of the chunk length (see also F1 of the security
analysis).** The design freezes `encryptionChunkSize` per share, but the upload endpoint
encrypts every body at whatever size it arrives, and the frontend always slices with the
*current* `share.chunkSize`. If an admin changes the chunk size, subsequent uploads into
existing encrypted shares (the `EditableUpload` scenario) are silently corrupted or fail
confusingly with `unexpected_chunk_index` – in the worst case a file uploads successfully
that can never be decrypted again. The pinning is thus only half implemented: the read
side relies on an invariant that the write side does not enforce. A length check in the
upload path (every chunk except the last must contain exactly `encryptionChunkSize`
plaintext bytes) would be a few lines and turns the failure loud instead of silent.

Further observations:

- **Quadratic buffering in the decrypt stream** (`encryption.service.ts:145`):
  `buffered = Buffer.concat([buffered, data])` per incoming stream piece. With 64-KB
  network chunks and 10-MB file chunks that is ~160 copies of growing buffers per chunk –
  functionally correct, but unnecessary CPU/memory load for large files. An array of
  buffers with a length counter (concatenating only once a chunk is complete) would be
  the usual stream idiom fix.
- **`getWrappingKey()` recomputes the HKDF on every call** – i.e. twice per
  chunk-upload request chain (unwrap) instead of once per process. Cheap, but a
  memoizable detail.
- **`pipeline(file.file, decryptionStream, …)` in `file.service.ts`** only logs errors.
  That is acceptable (NestJS aborts the response when the stream errors), but the error
  reaches the client as a severed connection without a structured message. An
  *immediately* failing unwrap, by contrast, cleanly throws a `403` – good layering.
- **Inconsistency edge case**: for `share.encrypted`, `getShareToken` derives the key
  from `password` without ensuring a password exists. The state "encrypted without a
  security password" is prevented at creation time, but could arise through future code
  paths (or direct DB changes) and would end here as an unhandled `TypeError`/500 instead
  of a clear error. A defensive check would be cheap.

## 4. Frontend quality

- **Code duplication enlarged**: the chunk-upload retry loop exists nearly identically in
  `pages/upload/index.tsx` and `components/upload/EditableUpload.tsx`; the new
  `share_encryption_key_required` branch was dutifully copied into both. The duplication
  is pre-existing, but this patch was an opportunity to extract it – now there is one
  more branch that has to be maintained twice.
- **`requestEncryptionKey` singleton at module level**: `pendingRequest` is global, not
  per share. Practically uncritical (a page works on one share), but a hidden coupling
  detail; a map keyed by `shareId` would be self-documenting. On the plus side: the
  password modal cannot be dismissed (`closeOnEscape: false` etc.), so the promise cannot
  hang forever without the user seeing it.
- **Clean form logic**: clearing the password disables the checkbox selection,
  `restrictToRecipients` resets `encrypted` – the invalid combinations are unreachable in
  the UI (and validated server-side regardless).
- Minor: in `showCreateUploadModal.tsx`, `passwordInputProps` is extracted to decorate
  `onChange` – solved idiomatically.

## 5. Database & migration

The migration is additive, backwards compatible (`DEFAULT false`, nullable columns) and
behavior-neutral for existing shares. `encryptionChunkSize` as its own column instead of
a config lookup is the right call (see pinning). The existing convention of `File.size`
as a string is respected (`parseInt` at the consuming site).

## 6. i18n

Backend and frontend strings were added only in `en-US`; the ~30 other locales get
fallbacks. This matches the project's usual workflow (translation via Crowdin or
similar), but should be kicked off before release – especially the checkbox description
explains security-relevant behavior ("password cannot be changed") and should reach users
in their own language.

## 7. Style nits

- Mixed use of `!=`/`!==` (`raw.length != …`, `chunkIndex != totalChunks`) – follows the
  inconsistent existing style; `===` would be preferable.
- `getStorageProvider` → `getShareStorageInfo` was renamed with all call sites updated –
  no dead remains (verified).
- The chunk layout is documented directly in the code ("Every encrypted chunk is stored
  as [nonce][ciphertext][auth tag]") – sparing the next reader from reverse engineering
  the storage format.

## 8. Overall verdict

An **above-average clean feature patch**: clear encapsulation, well-considered
operational edge cases (parameter/chunk-size pinning, cookie cleanup, error-code-driven
retry UX), consistent enforcement of the restrictions on both sides of the API boundary,
explanatory comments. The patch does not make the codebase harder to maintain – with two
exceptions that should be addressed before a merge:

1. **Add server-side chunk-length validation** (data-loss risk, section 3).
2. **Increase test depth**: unit tests for `EncryptionService` plus at least one
   multi-chunk and one tampering system test.

Recommended but not blocking: defuse the stream buffering, deduplicate the retry loop,
harden the cookie (see security analysis F2), kick off translations.
