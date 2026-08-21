# Security Analysis of the AES Encryption

Branch: `feat/share-file-encryption` (commit `26dc99e`)
Focus: correctness of the cryptographic implementation. Based on the full diff against
`main` as well as the surrounding existing code (guards, cookie handling, configuration).

## 1. Threat model

The feature protects **data at rest**: an attacker with access to the server's file
system or the S3 bucket (backup, stolen disk, misconfigured bucket) sees only
AES-256-GCM ciphertext. It additionally protects against an honest-but-curious operator,
**as long as** that operator neither reads live requests nor instruments the process –
because:

- It is **not end-to-end encryption**. The password (at creation/unlock time), the
  derived key (in every request cookie, unwrappable by the server) and the plaintext
  (during up-/download) all pass through the server.
- An actively compromised server can therefore capture future accesses. Shares already at
  rest that nobody accesses any more remain protected.

These limits are inherent to server-side encryption and are communicated correctly in the
UI text ("Store the files encrypted…"). The implementation has to be judged against the
chosen model – and against that model it holds up well.

## 2. Assessment of the cryptographic building blocks

### 2.1 Algorithm and mode – ✅ correct

AES-256-GCM (AEAD) via Node's `crypto.createCipheriv` – a solid, authenticated choice; no
home-grown crypto, no CBC/ECB, no "encrypt-then-nothing". The auth tag length is the full
GCM standard length (16 bytes), the nonce 12 bytes (the recommended length for GCM, no
GHASH-based nonce stretching needed).

### 2.2 Key derivation – ✅ correct, good parameters

- **Argon2id** with `memoryCost 65536 (64 MiB), timeCost 3, parallelism 4`,
  `hashLength 32`, 16-byte random salt (`crypto.randomBytes`). This is at or above the
  OWASP recommendations for Argon2id and appropriate for a password→key use case.
- The parameters are **explicitly pinned** rather than library defaults – important for
  long-term decryptability and a sign that operational reality was considered.
- **Domain separation**: for access control the password is hashed separately with its
  own salt (`argon.hash` in `share.service.ts`); the key is derived with the independent
  `encryptionSalt`. The stored password hash leaks no information about the file key. A
  per-share salt also prevents identical passwords from producing identical keys across
  shares.

### 2.3 Nonce handling – ✅ correct

A fresh 96-bit random nonce per chunk. For random GCM nonces the NIST rule of thumb is at
most 2³² encryptions per key; with 10-MB chunks that would correspond to ~40 exabytes per
share – practically unreachable. The key is additionally per share (and password).
Nonce-reuse risk: negligible as long as the system CSPRNG is intact. Key wrapping also
uses a fresh nonce per wrap.

### 2.4 AAD binding / integrity of the chunk structure – ✅ well thought out

AAD = `fileId:chunkIndex:totalChunks` prevents exactly the classic attacks on naively
chunk-wise encrypted files:

| Attack | Defense |
|---|---|
| Reordering chunks within a file | `chunkIndex` in AAD → tag failure |
| Truncating the file by whole chunks | `totalChunks` in AAD + final check `chunkIndex == totalChunks` in the decrypt stream's `flush()` |
| Extending the file by chunks | ditto (more chunks than `totalChunks` → count check fails) |
| Inserting a chunk from file B into file A | `fileId` (UUID) in AAD → tag failure |
| Inserting a chunk from another share | different key → tag failure |
| Byte-level ciphertext manipulation | GCM auth tag |

One remaining, acceptable gap: an attacker with storage **write** access can replace a
file with an **older complete version of the same file** (rollback), since no version
information is bound. That is outside the stated threat model (storage write access) and
common for at-rest encryption.

### 2.5 Key wrapping and cookie transport – ✅ correct at its core, with remarks

- Wrapping key via **HKDF-SHA256** from the `jwtSecret` (256 random bytes from the seed)
  with the fixed `info` string `"pingvin-share-enc-key-wrap"` – clean domain separation
  from JWT signing; an empty HKDF salt is fine with random IKM (RFC 5869).
- AAD = `shareId` at wrap/unwrap time prevents an enc cookie from share A being used
  against share B.
- `unwrapKey` checks the exact length (12+32+16) and catches **all** errors uniformly
  into a single `ForbiddenException` – no error oracle that would let format errors be
  distinguished from tag failures. The GCM tag check itself runs in constant time in
  OpenSSL.
- The raw key never exists in plaintext on the client side; the cookie is `httpOnly` (no
  XSS access to the key material itself).

### 2.6 Size back-calculation – ✅ correct

`getPlaintextSize` (storage size minus `chunks × 28`) and `getChunkCount`
(`max(1, ceil(size/chunkSize))` for empty files) are consistent with the upload path,
including the edge cases of an empty file and exactly full chunks. The decrypt stream
processes the last chunk separately in `flush()` and validates the total chunk count.

## 3. Findings

### F1 (Medium, integrity/availability): chunk length is not validated against the pinned chunk size at upload time

Decryption strictly relies on every stored chunk (except the last) being exactly
`encryptionChunkSize + 28` bytes. The upload path, however, **does not enforce this**: it
encrypts every received body at whatever size it arrives. The actual chunk size is
determined by the client (`file.slice(...)` with the **current** configuration value
`share.chunkSize`), while `encryptionChunkSize` was frozen when the share was created.

Concrete scenario without any attacker: an admin changes `share.chunkSize`, and
afterwards the owner uploads additional files into an **existing** encrypted share via
`EditableUpload`. The frontend now slices with the new size, the server happily encrypts
and stores those chunks – but `createDecryptionStream` will later split the stream at the
old boundaries, and the AAD `totalChunks` no longer matches either. Result: a
**permanently undecryptable file** that is only noticed at download time. (Depending on
the size ratio, the `expectedChunkIndex` check may fail confusingly instead; the upload
for this share is broken then, too.) A malicious uploader can bring about the same state
deliberately – that is not a confidentiality problem, but it renders server-side stored
data worthless even though the upload was acknowledged as "successful".

**Recommendation:** for uploads into encrypted shares, verify server-side that
`buffer.length == share.encryptionChunkSize` for all chunks except the last (and
`0 < length <= encryptionChunkSize` for the last one), otherwise reject with a clear
error. Additionally, the body-parser limit middleware value could be tied to the pinned
size for encrypted shares.

### F2 (Low–Medium, key transport): enc cookie without `Secure`/`SameSite`/`Max-Age`, unlimited validity of the wrap

`share_<id>_enc` is set with only `path: "/", httpOnly: true` – like the existing token
cookies, but this cookie carries **key material**:

- No `secure` flag: behind a misconfigured (HTTP) installation, the wrapped key would
  travel in the clear. The wrapping does protect against direct key extraction, but a
  captured cookie is fully usable.
- The wrapped key contains **no expiry**. A cookie exfiltrated once remains unwrappable
  until the `jwtSecret` is rotated. Practical impact is limited because every file access
  additionally requires the (time-limited, password-renewable) share token via
  `FileSecurityGuard` – the cookie alone opens no door. Defense in depth would still be:
  include a timestamp in the wrap AAD/payload and check it against a maximum age at
  unwrap time, plus `secure: true` (or configuration-dependent) and an explicit
  `sameSite`.

### F3 (Info): `jwtSecret` becomes a cryptographic master key

The wrapping key depends on the `jwtSecret`. That is convenient (rotation invalidates all
enc cookies; users simply re-enter the password — the data itself depends only on the
password), but it raises the criticality of this one value: anyone with the `jwtSecret`
and captured cookies obtains file keys. A separate wrapping secret, likewise stored in
the config store, would decouple this; given the threat model (both live in the same
database) the gain is small. Not a bug, a deliberate architecture – but it should be
documented.

### F4 (Info, accepted trade-off): no virus scan for encrypted shares

`clamScanService.checkAndRemove` is skipped for encrypted shares – logical, since no key
is available. Consequence: encrypted shares are a channel to distribute malware past the
scanner. Operators who deliberately run ClamAV should know this; possibly an admin option
to disable encryption, or scanning the chunk at the moment of upload (where the plaintext
is in memory anyway), would be worth considering.

### F5 (Info): brute-force and DoS considerations of the token endpoint

`POST /shares/:id/token` first verifies the Argon2 hash and then derives the key – two
memory-hard operations (~64 MiB, t=3) per request with a correct password, one per failed
attempt. The existing throttling (20 requests / 5 min) bounds both online brute force
against the password and the memory-DoS lever. Adequate; for very weak share passwords,
offline brute force against stolen ciphertext + salt remains the relevant attack – the
expensive Argon2id derivation helps here but does not replace a good password. The new
configurable password policy from `main` (#189) meshes well with this.

### F6 (Info): error behavior during streaming downloads

If the tag check fails mid-download, the HTTP headers (including `Content-Length` and
status 200) have already been sent; the client receives an aborted body. Plaintext of
earlier chunks that was already delivered stays delivered – with chunk-wise AEAD
streaming decryption this is unavoidable and acceptable, as long as clients detect the
abort (they do, via the length mismatch). Important and correctly implemented: it never
emits **unauthenticated plaintext** – each chunk is only pushed after its `final()` check
succeeds.

### F7 (Low): minor observations

- `ShareDTO` exposes `encrypted` publicly – needed by the UI; it merely tells an
  unauthenticated visitor that attacking the password would be worthwhile. Minor.
- Changing/removing the password of encrypted shares is cleanly blocked server-side
  (`updateShare`), including the `removePassword` path – not just in the UI.
- The preview restriction exists only in the frontend; the backend endpoint still serves
  inline with `download=false` (with `CSP: sandbox`). Since the content is delivered
  decrypted anyway, this is not a vulnerability, just a UI/backend asymmetry.
- Reverse shares: an anonymous uploader can create an encrypted share whose password the
  reverse-share creator does not know – not a security problem, but a possible support
  case.

## 4. Overall verdict

The cryptography is **technically correct and implemented with above-average care**: the
right AEAD mode, a strong and pinned KDF, clean salt and domain separation, fresh nonces,
a well-thought-out AAD binding against structural manipulation, uniform error paths
without oracles, and consistent server-side disabling of incompatible features. There is
**no finding that breaks the confidentiality of data at rest**.

Action is needed primarily on **F1** (missing chunk-length validation → data-loss risk on
chunk-size changes, unnoticed by the server) and, as hardening, on **F2** (cookie
attributes and expiry of the wrapped key).
