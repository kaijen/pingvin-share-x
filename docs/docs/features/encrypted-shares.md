---
id: encrypted-shares
---

# Encrypted Shares

When creating a share, you can enable the **"Encrypt files"** option in the security
settings. The files of the share are then stored encrypted with **AES-256** on the
server — whether you use local storage or S3. Anyone with access to the storage itself
(disk, backup, S3 bucket) only sees ciphertext.

## How it works

- Encryption requires a **share password**. The encryption key is derived from that
  password (using Argon2id) and is **never stored on the server**.
- After creating or unlocking a share with the password, the browser receives the key in
  a wrapped form as an HTTP-only cookie. If the cookie is lost (new browser, expired
  session), simply re-enter the share password to continue uploading or downloading.
- Every file is encrypted chunk by chunk with AES-256-GCM. The chunks are bound to their
  file and position, so tampering with the stored data — modifying, reordering or
  truncating it — is detected when the file is downloaded.

:::warning No password recovery
Since the key is derived from the share password and never stored, the files are
unrecoverable without the password. If the password is lost, the files of the share
cannot be decrypted — not even by the server administrator.
:::

## Limitations

Some features are not available for encrypted shares, because the server does not hold
the key:

| Feature | Behavior with encrypted shares |
| --- | --- |
| **Changing or removing the password** | Not possible. The key is derived from the password, so changing it would require re-encrypting all files. |
| **ZIP download ("Download all")** | Disabled. The archive would have to be created and stored on the server in plaintext. |
| **File previews** | Disabled. |
| **ClamAV scanning** | Encrypted files are **not** scanned, since the server cannot decrypt them after the upload has completed. |
| **Direct S3 transfers** | Uploads and downloads are always proxied through the backend so it can encrypt and decrypt the chunks. Pre-signed URLs are not used. See the [S3 docs](../setup/s3.md) for the implications. |
| **Restricted shares** | A share cannot be both encrypted and restricted to specific recipients, since restricted shares have no password to derive the key from. |

## Note for admins

Encryption protects the files **at rest**. It is not end-to-end encryption: the backend
encrypts uploaded chunks and decrypts downloaded chunks in memory, so the server briefly
handles plaintext while transfers are running. Use HTTPS in front of Pingvin Share X so
the share password and the key cookie are protected in transit.

For encrypted shares, the chunk size configured under `share.chunkSize` is pinned per
share at creation time, so files that are already uploaded stay decryptable even if the
global chunk size is changed later. Avoid changing the chunk size while encrypted shares
are still open for uploads, as in-progress uploads assume the chunk size the share was
created with.
