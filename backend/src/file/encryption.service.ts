import { ForbiddenException, Injectable } from "@nestjs/common";
import * as argon from "argon2";
import * as crypto from "crypto";
import { I18nService } from "nestjs-i18n";
import { Transform } from "stream";
import { ConfigService } from "src/config/config.service";

const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;

// Every encrypted chunk is stored as [nonce][ciphertext][auth tag]
export const CHUNK_OVERHEAD = NONCE_LENGTH + TAG_LENGTH;

// Pinned explicitly: relying on the library defaults would make existing shares
// undecryptable as soon as argon2 changes them.
const KEY_DERIVATION_OPTIONS = {
  type: argon.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

@Injectable()
export class EncryptionService {
  constructor(
    private config: ConfigService,
    private readonly i18n: I18nService,
  ) {}

  generateSalt() {
    return crypto.randomBytes(SALT_LENGTH).toString("base64");
  }

  // The share password is hashed with argon2 for access control. The encryption key
  // is derived from the same password but with a separate salt, so the stored hash
  // doesn't reveal anything about the key.
  async deriveKey(password: string, salt: string): Promise<Buffer> {
    return argon.hash(password, {
      ...KEY_DERIVATION_OPTIONS,
      salt: Buffer.from(salt, "base64"),
      hashLength: KEY_LENGTH,
      raw: true,
    });
  }

  // The key is never persisted. It's handed to the client wrapped in a cookie and
  // unwrapped again on every upload and download request.
  wrapKey(key: Buffer, shareId: string) {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv(
      "aes-256-gcm",
      this.getWrappingKey(),
      nonce,
    );
    cipher.setAAD(Buffer.from(shareId, "utf8"));

    const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);

    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString(
      "base64url",
    );
  }

  // Throws if the cookie is missing, malformed or belongs to a different share. The
  // client recovers by entering the share password again to get a fresh cookie.
  unwrapKey(wrappedKey: string, shareId: string): Buffer {
    try {
      const raw = Buffer.from(wrappedKey ?? "", "base64url");

      if (raw.length != NONCE_LENGTH + KEY_LENGTH + TAG_LENGTH)
        throw new Error("Invalid wrapped encryption key");

      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        this.getWrappingKey(),
        raw.subarray(0, NONCE_LENGTH),
      );
      decipher.setAAD(Buffer.from(shareId, "utf8"));
      decipher.setAuthTag(raw.subarray(raw.length - TAG_LENGTH));

      return Buffer.concat([
        decipher.update(raw.subarray(NONCE_LENGTH, raw.length - TAG_LENGTH)),
        decipher.final(),
      ]);
    } catch {
      throw new ForbiddenException(
        this.i18n.t("file.encryptionKeyRequired"),
        "share_encryption_key_required",
      );
    }
  }

  encryptChunk(
    key: Buffer,
    plaintext: Buffer,
    fileId: string,
    chunkIndex: number,
    totalChunks: number,
  ) {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(this.getChunkAad(fileId, chunkIndex, totalChunks));

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
  }

  createDecryptionStream(
    key: Buffer,
    fileId: string,
    plaintextSize: number,
    chunkSize: number,
  ) {
    const encryptedChunkSize = chunkSize + CHUNK_OVERHEAD;
    const totalChunks = this.getChunkCount(plaintextSize, chunkSize);

    const decryptChunk = (encrypted: Buffer, chunkIndex: number) => {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        encrypted.subarray(0, NONCE_LENGTH),
      );
      decipher.setAAD(this.getChunkAad(fileId, chunkIndex, totalChunks));
      decipher.setAuthTag(encrypted.subarray(encrypted.length - TAG_LENGTH));

      return Buffer.concat([
        decipher.update(
          encrypted.subarray(NONCE_LENGTH, encrypted.length - TAG_LENGTH),
        ),
        decipher.final(),
      ]);
    };

    let buffered = Buffer.alloc(0);
    let chunkIndex = 0;

    return new Transform({
      transform(data: Buffer, _encoding, callback) {
        buffered = Buffer.concat([buffered, data]);

        try {
          // The last chunk is shorter than the others, so it's left to flush()
          while (
            chunkIndex < totalChunks - 1 &&
            buffered.length >= encryptedChunkSize
          ) {
            this.push(
              decryptChunk(
                buffered.subarray(0, encryptedChunkSize),
                chunkIndex,
              ),
            );
            buffered = buffered.subarray(encryptedChunkSize);
            chunkIndex++;
          }
          callback();
        } catch (e) {
          callback(e as Error);
        }
      },
      flush(callback) {
        try {
          if (buffered.length > 0) {
            this.push(decryptChunk(buffered, chunkIndex));
            chunkIndex++;
          }

          if (chunkIndex != totalChunks)
            throw new Error(
              `Expected ${totalChunks} encrypted chunks but got ${chunkIndex}`,
            );

          callback();
        } catch (e) {
          callback(e as Error);
        }
      },
    });
  }

  getPlaintextSize(storedSize: number, chunkSize: number) {
    const chunkCount = Math.ceil(storedSize / (chunkSize + CHUNK_OVERHEAD));
    return storedSize - chunkCount * CHUNK_OVERHEAD;
  }

  private getChunkCount(plaintextSize: number, chunkSize: number) {
    // An empty file is still uploaded as a single (empty) chunk
    return Math.max(1, Math.ceil(plaintextSize / chunkSize));
  }

  // Binding the chunk position into the AAD prevents chunks from being reordered
  // or the file from being truncated without the auth tag check failing.
  private getChunkAad(
    fileId: string,
    chunkIndex: number,
    totalChunks: number,
  ): Buffer {
    return Buffer.from(`${fileId}:${chunkIndex}:${totalChunks}`, "utf8");
  }

  private getWrappingKey() {
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        this.config.get("internal.jwtSecret"),
        "",
        "pingvin-share-enc-key-wrap",
        KEY_LENGTH,
      ),
    );
  }
}
