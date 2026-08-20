-- AlterTable
ALTER TABLE "Share" ADD COLUMN "encrypted" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Share" ADD COLUMN "encryptionSalt" TEXT;
ALTER TABLE "Share" ADD COLUMN "encryptionChunkSize" INTEGER;
