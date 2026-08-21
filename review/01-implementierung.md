# AES-Verschlüsselung von Shares – Erklärung der Implementierung

Branch: `feat/share-file-encryption` (Commit `26dc99e` – „feat(share): encrypt files at rest with AES-256")

Dieses Dokument erklärt, wie die Dateiverschlüsselung in Pingvin Share funktioniert – vom
Anlegen eines verschlüsselten Shares über den Upload bis zum Download. Es richtet sich an
Leser, die den Code nachvollziehen wollen, ohne jede Zeile selbst lesen zu müssen.

## 1. Was das Feature macht

Beim Erstellen eines Shares kann der Nutzer zusätzlich zum Passwortschutz die Option
**„Encrypt files"** aktivieren. Die Dateien des Shares werden dann **auf dem Server
verschlüsselt gespeichert** (at rest), und zwar mit **AES-256-GCM**. Der
Verschlüsselungsschlüssel wird **aus dem Share-Passwort abgeleitet und niemals auf dem
Server gespeichert**. Wer die Festplatte des Servers oder den S3-Bucket in die Hände
bekommt, sieht nur Ciphertext.

Wichtig für die Einordnung: Es handelt sich **nicht um Ende-zu-Ende-Verschlüsselung**.
Die Ver- und Entschlüsselung passiert im Backend – der Server sieht beim Upload und
Download den Klartext sowie beim Anlegen/Entsperren das Passwort. Geschützt wird der
Ruhezustand der Daten, nicht der Transportweg durch den Server.

## 2. Die Schlüsselhierarchie

Es gibt zwei voneinander unabhängige Schlüssel:

```
Share-Passwort ──argon2id(+ encryptionSalt)──▶ Dateischlüssel (32 Byte, AES-256)
                                                    │
                                                    │  wird nie gespeichert, nur…
                                                    ▼
jwtSecret ──HKDF-SHA256("pingvin-share-enc-key-wrap")──▶ Wrapping-Schlüssel
                                                    │
                                                    ▼
                              „wrapped key" = AES-256-GCM(Dateischlüssel),
                              AAD = shareId → landet als Cookie beim Client
```

1. **Dateischlüssel** (`EncryptionService.deriveKey`,
   `backend/src/file/encryption.service.ts:39`): Aus dem Share-Passwort wird per
   **Argon2id** (memoryCost 64 MiB, timeCost 3, parallelism 4, 16-Byte-Zufallssalt) ein
   32-Byte-Schlüssel abgeleitet. Die Argon2-Parameter sind bewusst im Code festgenagelt
   (`KEY_DERIVATION_OPTIONS`), damit ein Bibliotheks-Update mit neuen Defaults bestehende
   Shares nicht unentschlüsselbar macht.

   Das dafür verwendete Salt (`encryptionSalt`) ist **ein anderes** als das Salt des
   Argon2-Hashes, mit dem das Passwort für die Zugriffskontrolle geprüft wird. Der in der
   Datenbank gespeicherte Passwort-Hash verrät dadurch nichts über den Schlüssel.

2. **Wrapping-Schlüssel** (`getWrappingKey`, `encryption.service.ts:207`): Da der
   Dateischlüssel nie gespeichert wird, muss der Client ihn bei jedem Upload-/
   Download-Request mitliefern. Damit der rohe Schlüssel nicht im Klartext im Browser
   liegt, wird er serverseitig „eingewickelt": AES-256-GCM mit einem Schlüssel, der per
   HKDF-SHA256 aus dem internen `jwtSecret` abgeleitet wird. Als AAD (Additional
   Authenticated Data) dient die `shareId` – ein Cookie von Share A lässt sich dadurch
   nicht für Share B verwenden.

Der so „gewrappte" Schlüssel (`nonce ‖ ciphertext ‖ tag`, base64url) wird als
**httpOnly-Cookie** `share_<shareId>_enc` gesetzt (`share.controller.ts`,
`setEncryptionKeyCookie`) – einmal beim Erstellen des Shares und jedes Mal, wenn ein
Besucher das Passwort korrekt eingibt (`POST /shares/:id/token`).

## 3. Datenmodell

Migration `20260820120000_add_share_encryption` ergänzt drei Spalten am `Share`:

| Feld | Bedeutung |
|---|---|
| `encrypted` (Boolean, default false) | Share ist verschlüsselt |
| `encryptionSalt` (String, nullable) | Salt der Argon2id-Schlüsselableitung (base64) |
| `encryptionChunkSize` (Int, nullable) | Beim Erstellen eingefrorene Chunk-Größe |

`encryptionChunkSize` wird beim Anlegen des Shares aus der Server-Konfiguration
`share.chunkSize` (Default 10 MB) übernommen und **pro Share fixiert**
(`share.service.ts:169 ff.`). Grund: Ein Admin kann die globale Chunk-Größe jederzeit
ändern – die Chunk-Grenzen bereits verschlüsselter Dateien dürfen sich dadurch nicht
verschieben, sonst wäre die Entschlüsselung nicht mehr möglich.

## 4. Das Chunk-Format

Uploads laufen in Pingvin Share ohnehin in Chunks (Frontend schneidet die Datei in
`share.chunkSize`-Stücke). Jeder Klartext-Chunk wird **einzeln** verschlüsselt und so
gespeichert:

```
[ Nonce: 12 Byte ][ Ciphertext: n Byte ][ GCM-Auth-Tag: 16 Byte ]
```

Der Overhead pro Chunk ist also konstant 28 Byte (`CHUNK_OVERHEAD`). Die Nonce wird pro
Chunk zufällig erzeugt (`crypto.randomBytes(12)`).

Als **AAD** wird `"${fileId}:${chunkIndex}:${totalChunks}"` gebunden
(`getChunkAad`, `encryption.service.ts:199`). Das sorgt dafür, dass beim Entschlüsseln
auffliegt, wenn jemand am Ciphertext manipuliert:

- Chunks **umsortieren** → `chunkIndex` stimmt nicht mehr → Auth-Tag-Prüfung schlägt fehl.
- Datei **kürzen/verlängern** → `totalChunks` bzw. die Chunk-Zählung im
  Entschlüsselungs-Stream stimmt nicht → Fehler.
- Chunks **zwischen Dateien tauschen** → `fileId` (UUID) stimmt nicht → Fehler.

Da die gespeicherte Datei größer ist als der Klartext, wird in der Datenbank immer die
**Klartextgröße** abgelegt. `getPlaintextSize` rechnet nach dem letzten Chunk aus der
Größe auf dem Datenträger zurück: Anzahl der Chunks × 28 Byte abziehen. Eine leere Datei
wird als ein einzelner leerer Chunk (28 Byte) gespeichert.

## 5. Ablauf: Share erstellen

`ShareService.create` (`share.service.ts:88 ff.`):

1. Validierung: `encrypted: true` ohne Passwort wird abgelehnt
   (`share.encryptionRequiresPassword`) – ohne Passwort gäbe es nichts, woraus man den
   Schlüssel ableiten könnte.
2. Salt erzeugen, Schlüssel aus dem noch im Klartext vorliegenden Passwort ableiten,
   Schlüssel wrappen. Direkt danach wird das Passwort wie bisher durch seinen
   Argon2-Hash ersetzt – weder Passwort noch Schlüssel werden gespeichert.
3. Share mit `encryptionSalt` und eingefrorener `encryptionChunkSize` anlegen.
4. Der Controller setzt das `share_<id>_enc`-Cookie aus dem zurückgegebenen
   `wrappedEncryptionKey`.

## 6. Ablauf: Upload

`FileController.create` liest das Cookie und reicht es bis zum Storage-Provider durch.
Beide Provider (`local.service.ts`, `s3.service.ts`) machen dasselbe:

1. Ist der Share verschlüsselt, wird der Schlüssel per `unwrapKey` aus dem Cookie
   ausgepackt. Fehlt das Cookie oder passt es nicht zum Share, gibt es eine
   `ForbiddenException` mit dem Fehlercode `share_encryption_key_required`.
2. Der empfangene Klartext-Chunk wird mit `encryptChunk` verschlüsselt und statt des
   Klartexts gespeichert (lokal: `fs.appendFile` an die tmp-Datei; S3: als Part eines
   Multipart-Uploads).
3. Beim letzten Chunk wird die Klartextgröße via `getPlaintextSize` berechnet und in die
   `File`-Tabelle geschrieben.

Besonderheit lokal: Die Prüfung des erwarteten Chunk-Index rechnet bei verschlüsselten
Shares mit `encryptionChunkSize + 28`, weil die Datei auf der Platte pro Chunk 28 Byte
größer ist als der Klartext.

Besonderheit S3: **Direkte Browser-Uploads per Pre-signed URL sind für verschlüsselte
Shares deaktiviert** (`file.service.ts`, `isDirectUploadSupported` /
`completePreSignedUpload`) – die Chunks müssen durchs Backend, sonst könnte niemand
verschlüsseln.

Das Frontend behandelt den Fehlercode `share_encryption_key_required` elegant: Es öffnet
den Passwort-Dialog (`requestEncryptionKey.ts`), holt sich über `POST /shares/:id/token`
ein frisches Cookie und wiederholt denselben Chunk. Parallele Uploads teilen sich dabei
ein einziges Passwort-Modal (`pendingRequest`-Singleton).

## 7. Ablauf: Download

`FileController.getFile`:

1. Für verschlüsselte S3-Shares wird der sonst übliche Redirect auf eine Pre-signed
   Download-URL übersprungen – der Stream muss durchs Backend zur Entschlüsselung.
2. `FileService.get` packt den Schlüssel aus dem Cookie aus, liest die Klartextgröße aus
   der Datenbank (die Storage-Größe wäre die falsche) und hängt einen
   **Transform-Stream** (`createDecryptionStream`) hinter den Storage-Stream.

Der Transform-Stream puffert Bytes, bis ein vollständiger verschlüsselter Chunk
(`encryptionChunkSize + 28`) beisammen ist, entschlüsselt ihn und reicht den Klartext
weiter. Der letzte (kürzere) Chunk wird in `flush()` verarbeitet. Am Ende wird geprüft,
dass exakt `totalChunks` Chunks gesehen wurden – eine abgeschnittene Datei fällt so auf.
Schlägt irgendwo die Auth-Tag-Prüfung fehl, bricht der Stream mit Fehler ab.

## 8. Bewusste Funktionseinschränkungen

Für verschlüsselte Shares sind konsequent (jeweils im Backend erzwungen und im Frontend
ausgeblendet) deaktiviert:

| Feature | Warum |
|---|---|
| **ZIP-Download / „Download all"** | Das ZIP-Archiv würde im Klartext auf dem Server erzeugt und gespeichert. |
| **Datei-Preview** | Vorschau ist im UI ausgeblendet (`FileList.tsx`). |
| **Passwort ändern/entfernen** | Der Schlüssel hängt am Passwort; eine Änderung würde Re-Encryption aller Dateien erfordern. `updateShare` lehnt das ab (`share.encryptedPasswordLocked`), das Edit-Modal zeigt stattdessen einen Hinweis. |
| **ClamAV-Virenscan** | Der Server hat nach Abschluss des Uploads keinen Schlüssel mehr, kann also nicht scannen. |
| **Pre-signed S3-Up-/Downloads** | Ver-/Entschlüsselung muss durch das Backend laufen. |
| **Kombination mit „restrict to recipients"** | Diese Shares haben kein Passwort, also keine Schlüsselquelle (Frontend setzt `encrypted` zurück). |

Der UI-Beschreibungstext der Checkbox benennt diese Konsequenzen ehrlich („The key is
derived from the password and never stored, so the password can't be changed or recovered
afterwards…").

## 9. Cookie-Lebenszyklus

- `share_<id>_enc` wird zusammen mit `share_<id>_token` gesetzt und in
  `clearShareTokenCookies` auch zusammen mit diesem wieder aufgeräumt (der Cookie-Name
  wird per `_token$` → `_enc`-Ersetzung abgeleitet).
- Geht das Cookie verloren (Browserwechsel, abgelaufen, gelöscht), führt jeder Zugriff zu
  `share_encryption_key_required`; der Nutzer gibt das Passwort erneut ein und erhält ein
  frisches Cookie. Der Server kann den Schlüssel nicht wiederherstellen – ohne Passwort
  sind die Daten endgültig unlesbar (das ist der Sinn des Features).

## 10. Tests

Die Newman-Systemtests (`backend/test/newman-system-tests.json`) decken den Kern-Flow ab:
verschlüsselten Share anlegen → Datei hochladen → Share abschließen → Token holen →
entschlüsselten Inhalt herunterladen und vergleichen. Negativfälle: Anlegen ohne
Passwort, ZIP-Download, Passwortänderung.
