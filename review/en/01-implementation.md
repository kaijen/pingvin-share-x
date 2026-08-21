# AES Encryption of Shares – Explanation of the Implementation

Branch: `feat/share-file-encryption` (commit `26dc99e` – "feat(share): encrypt files at rest with AES-256")

This document explains how file encryption works in Pingvin Share – from creating an
encrypted share through upload to download. It is aimed at readers who want to understand
the code without having to read every line themselves.

## 1. What the feature does

When creating a share, the user can enable the **"Encrypt files"** option in addition to
password protection. The files of the share are then **stored encrypted on the server**
(at rest), using **AES-256-GCM**. The encryption key is **derived from the share password
and never stored on the server**. Anyone who gets hold of the server's disk or the S3
bucket sees nothing but ciphertext.

Important for context: this is **not end-to-end encryption**. Encryption and decryption
happen in the backend – the server sees the plaintext during upload and download, and the
password when the share is created or unlocked. What is protected is the data at rest,
not its path through the server.

## 2. The key hierarchy

There are two independent keys:

```
Share password ──argon2id(+ encryptionSalt)──▶ file key (32 bytes, AES-256)
                                                    │
                                                    │  is never stored, only…
                                                    ▼
jwtSecret ──HKDF-SHA256("pingvin-share-enc-key-wrap")──▶ wrapping key
                                                    │
                                                    ▼
                              "wrapped key" = AES-256-GCM(file key),
                              AAD = shareId → handed to the client as a cookie
```

1. **File key** (`EncryptionService.deriveKey`,
   `backend/src/file/encryption.service.ts:39`): a 32-byte key is derived from the share
   password using **Argon2id** (memoryCost 64 MiB, timeCost 3, parallelism 4, 16-byte
   random salt). The Argon2 parameters are deliberately pinned in the code
   (`KEY_DERIVATION_OPTIONS`) so that a library update with new defaults cannot render
   existing shares undecryptable.

   The salt used here (`encryptionSalt`) is **a different one** than the salt of the
   Argon2 hash used to verify the password for access control. The password hash stored
   in the database therefore reveals nothing about the key.

2. **Wrapping key** (`getWrappingKey`, `encryption.service.ts:207`): since the file key
   is never stored, the client has to supply it with every upload/download request. So
   that the raw key never sits in the browser in plaintext, it is "wrapped" server-side:
   AES-256-GCM with a key derived from the internal `jwtSecret` via HKDF-SHA256. The
   `shareId` serves as AAD (Additional Authenticated Data) – a cookie from share A can
   therefore not be used for share B.

The wrapped key (`nonce ‖ ciphertext ‖ tag`, base64url) is set as an **httpOnly cookie**
`share_<shareId>_enc` (`share.controller.ts`, `setEncryptionKeyCookie`) – once when the
share is created, and every time a visitor enters the correct password
(`POST /shares/:id/token`).

## 3. Data model

Migration `20260820120000_add_share_encryption` adds three columns to `Share`:

| Field | Meaning |
|---|---|
| `encrypted` (boolean, default false) | share is encrypted |
| `encryptionSalt` (string, nullable) | salt of the Argon2id key derivation (base64) |
| `encryptionChunkSize` (int, nullable) | chunk size frozen at creation time |

`encryptionChunkSize` is taken from the server configuration `share.chunkSize` (default
10 MB) when the share is created and **pinned per share** (`share.service.ts:169 ff.`).
Reason: an admin can change the global chunk size at any time – the chunk boundaries of
files that are already encrypted must not shift as a result, otherwise decryption would
become impossible.

## 4. The chunk format

Uploads in Pingvin Share are chunked anyway (the frontend slices the file into
`share.chunkSize` pieces). Each plaintext chunk is encrypted **individually** and stored
like this:

```
[ nonce: 12 bytes ][ ciphertext: n bytes ][ GCM auth tag: 16 bytes ]
```

The overhead per chunk is therefore a constant 28 bytes (`CHUNK_OVERHEAD`). The nonce is
generated randomly per chunk (`crypto.randomBytes(12)`).

The **AAD** is `"${fileId}:${chunkIndex}:${totalChunks}"`
(`getChunkAad`, `encryption.service.ts:199`). This makes tampering with the ciphertext
show up at decryption time:

- **Reordering** chunks → `chunkIndex` no longer matches → auth tag check fails.
- **Truncating/extending** the file → `totalChunks` or the chunk count in the decryption
  stream no longer matches → error.
- **Swapping chunks between files** → `fileId` (UUID) does not match → error.

Since the stored file is larger than the plaintext, the database always records the
**plaintext size**. After the last chunk, `getPlaintextSize` computes it back from the
size on disk: subtract number of chunks × 28 bytes. An empty file is stored as a single
empty chunk (28 bytes).

## 5. Flow: creating a share

`ShareService.create` (`share.service.ts:88 ff.`):

1. Validation: `encrypted: true` without a password is rejected
   (`share.encryptionRequiresPassword`) – without a password there would be nothing to
   derive the key from.
2. Generate the salt, derive the key from the password while it is still in plaintext,
   wrap the key. Immediately afterwards the password is replaced by its Argon2 hash as
   before – neither the password nor the key is ever stored.
3. Create the share with `encryptionSalt` and the frozen `encryptionChunkSize`.
4. The controller sets the `share_<id>_enc` cookie from the returned
   `wrappedEncryptionKey`.

## 6. Flow: upload

`FileController.create` reads the cookie and passes it down to the storage provider. Both
providers (`local.service.ts`, `s3.service.ts`) do the same thing:

1. If the share is encrypted, the key is unpacked from the cookie via `unwrapKey`. If the
   cookie is missing or does not match the share, a `ForbiddenException` with error code
   `share_encryption_key_required` is thrown.
2. The received plaintext chunk is encrypted with `encryptChunk` and stored instead of
   the plaintext (local: `fs.appendFile` to the tmp file; S3: as a part of a multipart
   upload).
3. On the last chunk, the plaintext size is computed via `getPlaintextSize` and written
   to the `File` table.

Local specifics: for encrypted shares, the expected-chunk-index check calculates with
`encryptionChunkSize + 28`, because the file on disk is 28 bytes larger per chunk than
the plaintext.

S3 specifics: **direct browser uploads via pre-signed URLs are disabled for encrypted
shares** (`file.service.ts`, `isDirectUploadSupported` / `completePreSignedUpload`) – the
chunks have to pass through the backend, otherwise nobody could encrypt them.

The frontend handles the `share_encryption_key_required` error code gracefully: it opens
the password dialog (`requestEncryptionKey.ts`), obtains a fresh cookie via
`POST /shares/:id/token`, and retries the same chunk. Parallel uploads share a single
password modal (`pendingRequest` singleton).

## 7. Flow: download

`FileController.getFile`:

1. For encrypted S3 shares, the usual redirect to a pre-signed download URL is skipped –
   the stream has to pass through the backend for decryption.
2. `FileService.get` unwraps the key from the cookie, reads the plaintext size from the
   database (the storage size would be the wrong one), and attaches a **transform
   stream** (`createDecryptionStream`) behind the storage stream.

The transform stream buffers bytes until a complete encrypted chunk
(`encryptionChunkSize + 28`) has accumulated, decrypts it and passes the plaintext on.
The last (shorter) chunk is processed in `flush()`. At the end it verifies that exactly
`totalChunks` chunks were seen – a truncated file is caught this way. If the auth tag
check fails anywhere, the stream aborts with an error.

## 8. Deliberate feature restrictions

For encrypted shares the following are consistently disabled (each enforced in the
backend and hidden in the frontend):

| Feature | Why |
|---|---|
| **ZIP download / "Download all"** | The archive would be created and stored on the server in plaintext. |
| **File preview** | Preview is hidden in the UI (`FileList.tsx`). |
| **Changing/removing the password** | The key is tied to the password; changing it would require re-encrypting everything. `updateShare` rejects it (`share.encryptedPasswordLocked`), the edit modal shows a notice instead. |
| **ClamAV virus scan** | After the upload completes the server no longer has a key, so it cannot scan. |
| **Pre-signed S3 up-/downloads** | Encryption/decryption has to pass through the backend. |
| **Combination with "restrict to recipients"** | Those shares have no password, hence no key source (the frontend resets `encrypted`). |

The UI description text of the checkbox states these consequences honestly ("The key is
derived from the password and never stored, so the password can't be changed or recovered
afterwards…").

## 9. Cookie lifecycle

- `share_<id>_enc` is set together with `share_<id>_token` and is also cleaned up
  together with it in `clearShareTokenCookies` (the cookie name is derived via a
  `_token$` → `_enc` replacement).
- If the cookie is lost (browser change, expired, deleted), every access results in
  `share_encryption_key_required`; the user re-enters the password and receives a fresh
  cookie. The server cannot recover the key – without the password the data is
  permanently unreadable (which is the point of the feature).

## 10. Tests

The Newman system tests (`backend/test/newman-system-tests.json`) cover the core flow:
create encrypted share → upload file → complete share → obtain token → download the
decrypted content and compare it. Negative cases: creation without a password, ZIP
download, password change.
