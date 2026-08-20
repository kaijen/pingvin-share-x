import {
  Inject,
  Injectable,
  Logger,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Cache } from "cache-manager";
import { EncryptionService } from "./encryption.service";
import { LocalFileService } from "./local.service";
import { S3FileService } from "./s3.service";
import { ConfigService } from "src/config/config.service";
import { pipeline, Readable } from "stream";
import { PrismaService } from "../prisma/prisma.service";
import { EmailService } from "src/email/email.service";
import { I18nService } from "nestjs-i18n";

const UPDATED_AT_THROTTLE_MS = 5 * 60 * 1000;
const DOWNLOAD_NOTIFICATION_COOLDOWN_MS = 15 * 60 * 1000;

@Injectable()
export class FileService {
  constructor(
    private prisma: PrismaService,
    private localFileService: LocalFileService,
    private s3FileService: S3FileService,
    private configService: ConfigService,
    private emailService: EmailService,
    private encryptionService: EncryptionService,
    private readonly i18n: I18nService,
    @Inject(CACHE_MANAGER) private cache: Cache,
  ) {}
  private readonly logger = new Logger(FileService.name);

  // Determine which service to use based on the current config value
  // shareId is optional -> can be used to overwrite a storage provider
  private getStorageService(
    storageProvider?: string,
  ): S3FileService | LocalFileService {
    if (storageProvider != undefined)
      return storageProvider == "S3"
        ? this.s3FileService
        : this.localFileService;
    return this.configService.get("s3.enabled")
      ? this.s3FileService
      : this.localFileService;
  }

  async create(
    data: string,
    chunk: { index: number; total: number },
    file: {
      id?: string;
      name: string;
    },
    shareId: string,
    wrappedEncryptionKey?: string,
  ) {
    await this.touchShare(shareId);
    const storageService = this.getStorageService();
    return storageService.create(
      data,
      chunk,
      file,
      shareId,
      wrappedEncryptionKey,
    );
  }

  private async touchShare(shareId: string) {
    const share = await this.prisma.share.findUnique({
      where: { id: shareId },
      select: { updatedAt: true },
    });
    if (!share) return;
    if (
      share.updatedAt &&
      Date.now() - share.updatedAt.getTime() < UPDATED_AT_THROTTLE_MS
    )
      return;
    await this.prisma.share.update({
      where: { id: shareId },
      data: { updatedAt: new Date() },
    });
  }

  async createPreSignedUploadUrls(
    shareId: string,
    fileName: string,
    totalChunks: number,
  ) {
    await this.touchShare(shareId);
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true, encrypted: true },
    });
    // Encrypted shares have to be proxied so the chunks can be encrypted on the way
    if (share?.storageProvider !== "S3" || share.encrypted) {
      return { directToS3: false };
    }
    const res = await this.s3FileService.createPreSignedUploadUrls(
      shareId,
      fileName,
      totalChunks,
    );
    return { directToS3: true, ...res };
  }

  async completePreSignedUpload(
    shareId: string,
    fileId: string,
    fileName: string,
    uploadId: string,
    parts: Array<{ ETag: string; PartNumber: number }>,
  ) {
    await this.touchShare(shareId);
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true, encrypted: true },
    });
    if (share?.storageProvider !== "S3") {
      throw new BadRequestException(this.i18n.t("file.s3NotSupported"));
    }
    if (share.encrypted) {
      throw new BadRequestException(
        this.i18n.t("file.encryptedNoDirectUpload"),
      );
    }
    return this.s3FileService.completePreSignedUpload(
      shareId,
      fileId,
      fileName,
      uploadId,
      parts,
    );
  }

  async abortPreSignedUpload(
    shareId: string,
    fileName: string,
    uploadId: string,
  ) {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true },
    });
    if (share?.storageProvider !== "S3") {
      throw new BadRequestException(this.i18n.t("file.s3NotSupported"));
    }
    return this.s3FileService.abortPreSignedUpload(shareId, fileName, uploadId);
  }

  async getPreSignedDownloadUrl(
    shareId: string,
    fileId: string,
    isDownload: boolean,
  ): Promise<string> {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true },
    });
    if (share?.storageProvider !== "S3") {
      throw new BadRequestException(this.i18n.t("file.s3NotSupported"));
    }
    return this.s3FileService.getPreSignedDownloadUrl(
      shareId,
      fileId,
      isDownload,
    );
  }

  async get(
    shareId: string,
    fileId: string,
    wrappedEncryptionKey?: string,
  ): Promise<File> {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
    });
    const storageService = this.getStorageService(share.storageProvider);
    const file = await storageService.get(shareId, fileId);

    if (!share.encrypted) return file;

    const key = this.encryptionService.unwrapKey(wrappedEncryptionKey, shareId);

    // The stored object is larger than the file itself, so the size always has to
    // come from the database instead of from the storage provider.
    const { size } = await this.prisma.file.findUnique({
      where: { id: fileId },
      select: { size: true },
    });

    const decryptionStream = this.encryptionService.createDecryptionStream(
      key,
      fileId,
      parseInt(size),
      share.encryptionChunkSize,
    );

    pipeline(file.file, decryptionStream, (error) => {
      if (error)
        this.logger.error(
          `Failed to decrypt file ${fileId} of share ${shareId}`,
          error.stack,
        );
    });

    return {
      metaData: { ...file.metaData, size },
      file: decryptionStream,
    };
  }

  async remove(shareId: string, fileId: string) {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true },
    });
    const storageService = this.getStorageService(share?.storageProvider);
    return storageService.remove(shareId, fileId);
  }

  async deleteAllFiles(shareId: string) {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { id: true, storageProvider: true },
    });
    const storageService = this.getStorageService(share?.storageProvider);
    return storageService.deleteAllFiles(shareId);
  }

  async getZip(shareId: string): Promise<Readable> {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true, encrypted: true },
    });
    if (share?.encrypted) {
      throw new BadRequestException(this.i18n.t("file.encryptedNoZip"));
    }
    const storageService = this.getStorageService(share?.storageProvider);
    return await storageService.getZip(shareId);
  }

  async notifyRecipientDownload(
    shareId: string,
    fileName: string,
    recipientId?: string,
  ) {
    try {
      if (
        !recipientId ||
        !this.configService.get("smtp.enabled") ||
        !this.configService.get("email.enableShareEmailRecipients") ||
        !this.configService.get("email.enableShareDownloadNotifications")
      )
        return;

      const notificationKey = `share-download-notification:${shareId}:${recipientId}`;
      if (await this.cache.get<true>(notificationKey)) return;

      const share = await this.prisma.share.findUnique({
        where: { id: shareId },
        select: {
          id: true,
          creator: { select: { email: true } },
          recipients: {
            where: { id: recipientId },
            select: { email: true },
          },
        },
      });

      const recipient = share?.recipients[0];
      if (!share?.creator?.email || !recipient) return;

      await this.cache.set(
        notificationKey,
        true,
        DOWNLOAD_NOTIFICATION_COOLDOWN_MS,
      );

      await this.emailService.sendShareDownloadNotification(
        share.creator.email,
        share.id,
        fileName,
        recipient.email,
      );
    } catch (e) {
      this.logger.error(
        `Failed to notify recipient download for share ${shareId}`,
        e instanceof Error ? e.stack : String(e),
      );
    }
  }

  async getShareStorageInfo(shareId: string) {
    const share = await this.prisma.share.findFirst({
      where: { id: shareId },
      select: { storageProvider: true, encrypted: true },
    });
    return {
      storageProvider: share?.storageProvider || "LOCAL",
      encrypted: share?.encrypted ?? false,
    };
  }

  async getFileName(shareId: string, fileId: string): Promise<string> {
    const file = await this.prisma.file.findFirst({
      where: { id: fileId, shareId },
      select: { name: true },
    });
    if (!file) throw new NotFoundException(this.i18n.t("file.notFound"));
    return file.name;
  }

  private async streamToUint8Array(stream: Readable): Promise<Uint8Array> {
    const chunks: Buffer[] = [];

    return new Promise((resolve, reject) => {
      stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      stream.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
      stream.on("error", reject);
    });
  }
}

export interface File {
  metaData: {
    id: string;
    size: string;
    createdAt: Date;
    mimeType: string | false;
    name: string;
    shareId: string;
  };
  file: Readable;
}
