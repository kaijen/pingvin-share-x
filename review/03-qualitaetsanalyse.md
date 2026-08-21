# Qualitätsanalyse der AES-Implementierung

Branch: `feat/share-file-encryption` (Commit `26dc99e`), Diff gegen `main`:
24 Dateien, ~1.020 Zeilen hinzugefügt. Diese Analyse bewertet Architektur, Code-Qualität,
Robustheit, Tests und Wartbarkeit – die kryptographische Korrektheit ist Gegenstand der
separaten Sicherheitsanalyse (`02-sicherheitsanalyse.md`).

## 1. Architektur und Design – Stärken

**Saubere Kapselung.** Die gesamte Kryptologik liegt in einem einzigen neuen
`EncryptionService` (218 Zeilen) mit klarer, kleiner API (`deriveKey`, `wrapKey`/
`unwrapKey`, `encryptChunk`, `createDecryptionStream`, `getPlaintextSize`). Storage-
Provider und Share-Service konsumieren sie nur; kein Krypto-Code ist über die Codebasis
verstreut. Konstanten (`NONCE_LENGTH`, `CHUNK_OVERHEAD`, …) sind zentral definiert und
werden exportiert statt dupliziert (`local.service.ts` importiert `CHUNK_OVERHEAD`).

**Symmetrische Integration in beide Storage-Provider.** Lokal und S3 folgen demselben
Muster (unwrap → encryptChunk → Klartextgröße beim letzten Chunk). Die Signatur von
`create(...)` wurde einheitlich um `wrappedEncryptionKey?` erweitert.

**Vorausschauendes Pinning.** Zwei Entscheidungen zeugen von Betriebserfahrung: die
Argon2-Parameter sind gegen Bibliotheks-Default-Änderungen gepinnt, und die Chunk-Größe
wird pro Share eingefroren (`encryptionChunkSize`), weil der Config-Wert admin-seitig
änderbar ist. (Dass das Pinning an einer Stelle nicht zu Ende gedacht ist, siehe Punkt 3.)

**Konsistente Feature-Abschaltung.** ZIP, Preview, Passwortänderung, ClamAV, Pre-signed
S3-Operationen: jede Inkompatibilität ist im Backend erzwungen **und** im Frontend
ausgeblendet, jeweils mit eigener i18n-Fehlermeldung. Besonders gut: der Cookie-Cleanup
(`clearShareTokenCookies`) räumt das neue `_enc`-Cookie zusammen mit dem `_token`-Cookie
auf – ein leicht zu übersehendes Detail.

**Kommentarqualität.** Die Kommentare erklären durchgehend das *Warum* („Pinned
explicitly: relying on the library defaults would make existing shares undecryptable…",
„Always store the size of the file itself, not the size it takes up on disk"). Das ist
genau die Sorte Kommentar, die bei Krypto-Code den Unterschied macht.

**Gute Fehler-Ergonomie im Frontend.** Der dedizierte Fehlercode
`share_encryption_key_required` wird im Upload-Retry-Pfad erkannt: Passwort-Modal öffnen,
Cookie erneuern, denselben Chunk wiederholen. Parallele Uploads teilen sich über das
`pendingRequest`-Singleton ein einziges Modal. Der UI-Beschreibungstext der
Verschlüsselungs-Checkbox kommuniziert die Konsequenzen (kein Passwortwechsel, kein
Preview/ZIP) ehrlich.

## 2. Tests – Lücken

Positiv: Die Newman-Systemtests decken den Happy Path Ende-zu-Ende ab (Anlegen → Upload →
Complete → Token → Download mit Inhaltsvergleich) plus drei Negativfälle (ohne Passwort,
ZIP, Passwortänderung).

Es fehlen jedoch:

- **Unit-Tests für `EncryptionService`** – der Service ist pure Logik ohne I/O und wäre
  trivial testbar. Gerade `getPlaintextSize`/`getChunkCount`/`createDecryptionStream`
  haben Randfälle (leere Datei, exakt volle Chunks, letzter Chunk = 1 Byte), die ein
  Systemtest mit einer 76-Byte-Datei nicht abdeckt.
- **Multi-Chunk-Szenario**: Der Systemtest lädt genau einen Chunk hoch. Die gesamte
  Stream-Rechunking-Logik (transform/flush, `expectedChunkIndex` mit Overhead) läuft im
  Test nie durch ihren interessanten Pfad.
- **Manipulations-Tests**: kein Test, dass ein verfälschter/verkürzter Ciphertext beim
  Download tatsächlich scheitert – das ist das zentrale Sicherheitsversprechen der
  AAD-Konstruktion.
- **Fehlendes/fremdes Cookie beim Download** (der `share_encryption_key_required`-Pfad).
- **S3-Pfad**: verständlich (Systemtests laufen lokal), aber die S3-Integration ist
  damit ungetestet.

## 3. Robustheit – Hauptbefund

**Fehlende serverseitige Validierung der Chunk-Länge (siehe auch F1 der
Sicherheitsanalyse).** Das Design friert `encryptionChunkSize` pro Share ein, aber der
Upload-Endpunkt verschlüsselt jeden Body in empfangener Größe, und das Frontend schneidet
immer mit dem *aktuellen* `share.chunkSize`. Ändert ein Admin die Chunk-Größe, sind
Folge-Uploads in bestehende verschlüsselte Shares (Szenario `EditableUpload`) still
korrupt oder scheitern verwirrend an `unexpected_chunk_index` – im schlimmsten Fall wird
eine Datei erfolgreich hochgeladen, die sich nie wieder entschlüsseln lässt. Das Pinning
ist damit nur zur Hälfte umgesetzt: Die Leseseite verlässt sich auf eine Invariante, die
die Schreibseite nicht durchsetzt. Eine Längenprüfung im Upload-Pfad (alle Chunks außer
dem letzten müssen exakt `encryptionChunkSize` Klartext-Bytes haben) wäre wenige Zeilen
und macht den Fehler laut statt leise.

Weitere Beobachtungen:

- **Quadratisches Buffering im Decrypt-Stream** (`encryption.service.ts:145`):
  `buffered = Buffer.concat([buffered, data])` pro eingehendem Stream-Stück. Bei
  64-KB-Netzwerk-Chunks und 10-MB-Dateichunks sind das ~160 Kopien wachsender Puffer pro
  Chunk – funktional korrekt, aber unnötige CPU-/Speicherlast bei großen Dateien. Ein
  Array von Buffern mit Längenzähler (concat erst bei vollständigem Chunk) wäre der
  übliche Stream-Idiom-Fix.
- **`getWrappingKey()` rechnet HKDF bei jedem Aufruf neu** – also zweimal pro
  Chunk-Upload-Request-Kette (unwrap) statt einmal pro Prozess. Billig, aber ein
  memoisierbares Detail.
- **`pipeline(file.file, decryptionStream, …)` in `file.service.ts`** loggt Fehler nur.
  Das ist akzeptabel (NestJS bricht die Response ab, wenn der Stream errort), aber der
  Fehler erreicht den Client als abgerissene Verbindung ohne strukturierte Meldung. Bei
  einem *sofort* scheiternden Unwrap wird dagegen sauber `403` geworfen – gutes Layering.
- **Inkonsistenz-Randfall**: `getShareToken` leitet bei `share.encrypted` den Schlüssel
  aus `password` ab, ohne abzusichern, dass ein Passwort existiert. Der Zustand
  „encrypted ohne Security-Passwort" wird bei der Erstellung verhindert, könnte aber
  durch künftige Codepfade (oder direkte DB-Änderung) entstehen und würde hier als
  unbehandelter `TypeError`/500 enden statt als klarer Fehler. Defensive Prüfung wäre
  billig.

## 4. Frontend-Qualität

- **Code-Duplikation vergrößert**: Der Chunk-Upload-Retry-Loop existiert nahezu identisch
  in `pages/upload/index.tsx` und `components/upload/EditableUpload.tsx`; der neue
  `share_encryption_key_required`-Zweig wurde pflichtgemäß in beide kopiert. Die
  Duplikation ist Bestand, aber der Patch war eine Gelegenheit, sie zu extrahieren –
  jetzt gibt es einen weiteren Zweig, der doppelt gepflegt werden muss.
- **`requestEncryptionKey`-Singleton auf Modulebene**: `pendingRequest` ist global, nicht
  pro Share. Praktisch unkritisch (eine Seite bearbeitet einen Share), aber ein
  verstecktes Kopplungsdetail; eine Map nach `shareId` wäre selbstdokumentierend.
  Positiv: das Passwort-Modal ist nicht schließbar (`closeOnEscape: false` etc.), daher
  kann das Promise nicht ewig hängen bleiben, ohne dass der Nutzer es sieht.
- **Saubere Formular-Logik**: Passwort leeren deaktiviert die Checkbox-Auswahl,
  `restrictToRecipients` setzt `encrypted` zurück – die unzulässigen Kombinationen sind
  im UI nicht erreichbar (und serverseitig trotzdem validiert).
- Kleinigkeit: In `showCreateUploadModal.tsx` wird `passwordInputProps` extrahiert, um
  `onChange` zu dekorieren – idiomatisch gelöst.

## 5. Datenbank & Migration

Die Migration ist additiv, rückwärtskompatibel (`DEFAULT false`, nullable Spalten) und
für bestehende Shares verhaltensneutral. `encryptionChunkSize` als eigene Spalte statt
Config-Lookup ist die richtige Entscheidung (siehe Pinning). Die bestehende Konvention
`File.size` als String wird respektiert (`parseInt` an der Konsumstelle).

## 6. i18n

Backend- und Frontend-Strings sind nur in `en-US` ergänzt; die ~30 anderen Locales
erhalten Fallbacks. Das entspricht dem üblichen Workflow des Projekts (Übersetzung via
Crowdin o. ä.), sollte aber vor Release angestoßen werden – gerade die
Checkbox-Beschreibung erklärt sicherheitsrelevantes Verhalten („Passwort nicht änderbar")
und sollte Nutzer in ihrer Sprache erreichen.

## 7. Stil-Kleinigkeiten

- Gemischte Verwendung von `!=`/`!==` (`raw.length != …`, `chunkIndex != totalChunks`) –
  folgt dem uneinheitlichen Bestandsstil, `===` wäre vorzuziehen.
- `getStorageProvider` → `getShareStorageInfo` wurde umbenannt und alle Aufrufer
  angepasst – keine toten Reste (geprüft).
- Das Chunk-Layout ist direkt im Code dokumentiert („Every encrypted chunk is stored as
  [nonce][ciphertext][auth tag]") – das erspart dem nächsten Leser das Reverse
  Engineering des Speicherformats.

## 8. Gesamturteil

Ein **überdurchschnittlich sauberer Feature-Patch**: klare Kapselung, durchdachte
Betriebs-Randfälle (Parameter-/Chunk-Size-Pinning, Cookie-Cleanup, Fehlercode-gestützte
Retry-UX), konsistente Durchsetzung der Einschränkungen auf beiden Seiten des API-Rands,
erklärende Kommentare. Die Codebasis wird durch den Patch nicht schlechter wartbar –
mit zwei Ausnahmen, die vor einem Merge adressiert werden sollten:

1. **Serverseitige Chunk-Längen-Validierung nachrüsten** (Datenverlust-Risiko, Punkt 3).
2. **Testtiefe erhöhen**: Unit-Tests für `EncryptionService` und mindestens ein
   Multi-Chunk- sowie ein Manipulations-Systemtest.

Empfehlenswert, aber nicht blockierend: Stream-Buffering entschärfen, Retry-Loop
deduplizieren, Cookie-Härtung (siehe Sicherheitsanalyse F2), Übersetzungen anstoßen.
