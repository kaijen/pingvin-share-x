# Sicherheitsanalyse der AES-Verschlüsselung

Branch: `feat/share-file-encryption` (Commit `26dc99e`)
Fokus: korrekte Implementierung der Kryptographie. Grundlage ist der vollständige Diff
gegen `main` sowie der umgebende Bestandscode (Guards, Cookie-Handling, Konfiguration).

## 1. Threat Model

Das Feature schützt **Daten im Ruhezustand**: Ein Angreifer mit Zugriff auf das
Dateisystem des Servers oder den S3-Bucket (Backup, geklauter Datenträger, fehlkonfigurierter
Bucket) sieht nur AES-256-GCM-Ciphertext. Zusätzlich schützt es gegen einen ehrlichen,
aber neugierigen Betreiber, **solange** dieser weder laufende Requests mitliest noch den
Prozess instrumentiert – denn:

- Es ist **keine Ende-zu-Ende-Verschlüsselung**. Passwort (beim Anlegen/Entsperren),
  abgeleiteter Schlüssel (in jedem Request-Cookie, vom Server entpackbar) und Klartext
  (beim Up-/Download) durchlaufen den Server.
- Ein aktiv kompromittierter Server kann daher künftige Zugriffe mitschneiden. Bereits
  ruhende Shares, auf die niemand mehr zugreift, bleiben geschützt.

Diese Grenzen sind inhärent für serverseitige Verschlüsselung und im UI-Text korrekt
kommuniziert („Store the files encrypted…"). Für das gewählte Modell ist die Umsetzung zu
bewerten – und die fällt überwiegend positiv aus.

## 2. Bewertung der kryptographischen Bausteine

### 2.1 Algorithmus und Modus – ✅ korrekt

AES-256-GCM (AEAD) über Node's `crypto.createCipheriv` – eine solide, authentifizierte
Wahl; keine Eigenbau-Krypto, kein CBC/ECB, kein „encrypt-then-nothing". Die
Auth-Tag-Länge ist die volle GCM-Standardlänge (16 Byte), Nonce 12 Byte (die für GCM
empfohlene Länge, kein GHASH-basiertes Nonce-Stretching nötig).

### 2.2 Schlüsselableitung – ✅ korrekt, gute Parameter

- **Argon2id** mit `memoryCost 65536 (64 MiB), timeCost 3, parallelism 4`,
  `hashLength 32`, 16-Byte-Zufallssalt (`crypto.randomBytes`). Das liegt auf bzw. über
  den OWASP-Empfehlungen für Argon2id und ist für einen Passwort→Schlüssel-Anwendungsfall
  angemessen.
- Die Parameter sind **explizit gepinnt** statt Bibliotheks-Defaults – wichtig für die
  langfristige Entschlüsselbarkeit und ein Zeichen, dass an Betriebsrealität gedacht wurde.
- **Domänentrennung**: Für die Zugriffskontrolle wird das Passwort separat mit eigenem
  Salt gehasht (`argon.hash` in `share.service.ts`), für den Schlüssel mit dem
  unabhängigen `encryptionSalt` abgeleitet. Der gespeicherte Passwort-Hash gibt keine
  Information über den Dateischlüssel preis. Salt pro Share verhindert zudem, dass
  gleiche Passwörter über Shares hinweg gleiche Schlüssel ergeben.

### 2.3 Nonce-Handling – ✅ korrekt

Pro Chunk eine frische 96-Bit-Zufallsnonce. Bei zufälligen GCM-Nonces gilt die
NIST-Faustregel von maximal 2³² Verschlüsselungen pro Schlüssel; bei 10-MB-Chunks
entspräche das ~40 Exabyte pro Share – praktisch unerreichbar. Der Schlüssel ist zudem
pro Share (und Passwort) individuell. Nonce-Reuse-Risiko: vernachlässigbar, sofern der
System-CSPRNG intakt ist. Auch das Key-Wrapping nutzt pro Wrap eine frische Nonce.

### 2.4 AAD-Bindung / Integrität der Chunk-Struktur – ✅ durchdacht

AAD = `fileId:chunkIndex:totalChunks` verhindert genau die klassischen Angriffe auf
naiv chunk-weise verschlüsselte Dateien:

| Angriff | Abwehr |
|---|---|
| Chunks innerhalb einer Datei umsortieren | `chunkIndex` in AAD → Tag-Fehler |
| Datei um ganze Chunks kürzen | `totalChunks` in AAD + Endprüfung `chunkIndex == totalChunks` im `flush()` des Decrypt-Streams |
| Datei um Chunks verlängern | dito (mehr Chunks als `totalChunks` → Zählung schlägt fehl) |
| Chunk aus Datei B in Datei A einsetzen | `fileId` (UUID) in AAD → Tag-Fehler |
| Chunk aus anderem Share einsetzen | anderer Schlüssel → Tag-Fehler |
| Byte-Manipulation im Ciphertext | GCM-Auth-Tag |

Ein verbleibender, akzeptabler Rest: Ein Angreifer mit Storage-**Schreib**zugriff kann
eine Datei durch eine **ältere vollständige Version derselben Datei** ersetzen
(Rollback), da keine Versionsinformation gebunden ist. Das liegt außerhalb des erklärten
Threat Models (Storage-Schreibzugriff) und ist bei At-rest-Verschlüsselung üblich.

### 2.5 Key-Wrapping und Cookie-Transport – ✅ im Kern korrekt, mit Anmerkungen

- Wrapping-Schlüssel per **HKDF-SHA256** aus dem `jwtSecret` (256 zufällige Bytes aus dem
  Seed) mit festem `info`-String `"pingvin-share-enc-key-wrap"` – saubere
  Domänenseparation vom JWT-Signieren; leeres HKDF-Salt ist bei zufälligem IKM in
  Ordnung (RFC 5869).
- AAD = `shareId` beim Wrap/Unwrap verhindert, dass ein Enc-Cookie von Share A gegen
  Share B eingesetzt wird.
- `unwrapKey` prüft die exakte Länge (12+32+16) und fängt **alle** Fehler einheitlich zu
  einer einzigen `ForbiddenException` – kein Fehler-Orakel, das Formatfehler von
  Tag-Fehlern unterscheiden ließe. Die GCM-Tag-Prüfung selbst läuft in OpenSSL
  konstantzeitig.
- Der rohe Schlüssel liegt clientseitig nie im Klartext vor; das Cookie ist `httpOnly`
  (kein Zugriff per XSS auf das Schlüsselmaterial selbst).

### 2.6 Größen-Rückrechnung – ✅ korrekt

`getPlaintextSize` (Storage-Größe minus `chunks × 28`) und `getChunkCount`
(`max(1, ceil(size/chunkSize))` für leere Dateien) sind konsistent mit dem Uploadpfad,
inklusive der Randfälle leere Datei und exakt volle Chunks. Der Decrypt-Stream
verarbeitet den letzten Chunk separat im `flush()` und validiert die Chunk-Gesamtzahl.

## 3. Findings

### F1 (Mittel, Integrität/Verfügbarkeit): Chunk-Länge wird beim Upload nicht gegen die gepinnte Chunk-Größe validiert

Die Entschlüsselung verlässt sich strikt darauf, dass jeder gespeicherte Chunk (außer dem
letzten) exakt `encryptionChunkSize + 28` Byte groß ist. Der Upload-Pfad **erzwingt das
aber nicht**: Er verschlüsselt jeden empfangenen Body in der Größe, in der er ankommt.
Die tatsächliche Chunk-Größe bestimmt der Client (`file.slice(...)` mit dem **aktuellen**
Konfigurationswert `share.chunkSize`), während `encryptionChunkSize` beim Anlegen des
Shares eingefroren wurde.

Konkretes Szenario ohne Angreifer: Admin ändert `share.chunkSize`, danach lädt der
Besitzer über `EditableUpload` weitere Dateien in einen **bestehenden** verschlüsselten
Share. Das Frontend schneidet nun mit der neuen Größe, der Server verschlüsselt und
speichert diese Chunks anstandslos – aber `createDecryptionStream` zerlegt den Stream
später an den alten Grenzen, und auch das AAD-`totalChunks` passt nicht mehr. Ergebnis:
**dauerhaft nicht entschlüsselbare Datei**, die erst beim Download auffällt. (Je nach
Größenverhältnis schlägt alternativ schon die `expectedChunkIndex`-Prüfung fehl; auch
dann ist der Upload für diesen Share kaputt.) Ein böswilliger Uploader kann denselben
Zustand gezielt herbeiführen – das ist kein Vertraulichkeitsproblem, macht aber
serverseitig gespeicherte Daten wertlos, obwohl der Upload mit „Erfolg" quittiert wurde.

**Empfehlung:** Beim Upload in verschlüsselte Shares serverseitig prüfen, dass
`buffer.length == share.encryptionChunkSize` für alle Chunks außer dem letzten (und
`0 < length <= encryptionChunkSize` für den letzten), sonst mit klarem Fehler ablehnen.
Zusätzlich könnte der Body-Parser-Limit-Middleware-Wert für verschlüsselte Shares an der
gepinnten Größe hängen.

### F2 (Niedrig–Mittel, Schlüsseltransport): Enc-Cookie ohne `Secure`/`SameSite`/`Max-Age`, unbegrenzte Gültigkeit des Wraps

`share_<id>_enc` wird nur mit `path: "/", httpOnly: true` gesetzt – wie die bestehenden
Token-Cookies, aber dieses Cookie trägt **Schlüsselmaterial**:

- Kein `secure`-Flag: Hinter einer fehlkonfigurierten (HTTP-)Installation ginge der
  gewrappte Schlüssel im Klartext über die Leitung. Das Wrapping schützt zwar vor
  direkter Schlüssel-Extraktion, aber ein mitgeschnittenes Cookie ist voll verwendbar.
- Der gewrappte Schlüssel enthält **kein Ablaufdatum**. Ein einmal exfiltriertes Cookie
  bleibt so lange entpackbar, bis das `jwtSecret` rotiert wird. Der praktische Impact ist
  begrenzt, weil jeder Dateizugriff zusätzlich den (befristeten, per Passwort erneuerbaren)
  Share-Token durch `FileSecurityGuard` erfordert – das Cookie allein öffnet keine Tür.
  Verteidigungstiefe wäre trotzdem: Timestamp mit ins Wrap-AAD/Payload aufnehmen und beim
  Unwrap gegen ein Maximalalter prüfen, plus `secure: true` (bzw. konfigurationsabhängig)
  und explizites `sameSite`.

### F3 (Info): `jwtSecret` wird zum kryptographischen Generalschlüssel

Der Wrapping-Schlüssel hängt am `jwtSecret`. Das ist praktisch (Rotation invalidiert alle
Enc-Cookies, Nutzer geben einfach das Passwort neu ein — die Daten selbst hängen nur am
Passwort), erhöht aber die Kritikalität dieses einen Werts: Wer `jwtSecret` und
mitgeschnittene Cookies hat, erhält Dateischlüssel. Ein separates, ebenfalls im
Config-Store abgelegtes Wrapping-Secret würde die Kopplung lösen; angesichts des Threat
Models (beides liegt in derselben DB) ist der Gewinn allerdings gering. Kein Fehler,
bewusste Architektur – sollte dokumentiert sein.

### F4 (Info, akzeptierter Trade-off): Kein Virenscan für verschlüsselte Shares

`clamScanService.checkAndRemove` wird für verschlüsselte Shares übersprungen –
folgerichtig, da kein Schlüssel vorliegt. Konsequenz: Verschlüsselte Shares sind ein
Kanal, über den Malware am Scanner vorbei verteilt werden kann. Betreiber, die ClamAV
bewusst einsetzen, sollten das wissen; ggf. wäre eine Admin-Option „Verschlüsselung
deaktivieren" oder ein Scan des Chunks im Moment des Uploads (wo der Klartext ohnehin im
Speicher ist) eine Überlegung wert.

### F5 (Info): Brute-Force- und DoS-Betrachtung des Token-Endpunkts

`POST /shares/:id/token` verifiziert erst den Argon2-Hash und leitet danach den Schlüssel
ab – zwei speicherharte Operationen (~64 MiB, t=3) pro Request mit korrektem Passwort,
eine pro Fehlversuch. Das bestehende Throttling (20 Requests / 5 min) begrenzt sowohl
Online-Brute-Force aufs Passwort als auch den Memory-DoS-Hebel. Angemessen; bei sehr
schwachen Share-Passwörtern bleibt Offline-Brute-Force gegen gestohlenen Ciphertext
+ Salt der relevante Angriff – hier hilft die kostspielige Argon2id-Ableitung, ersetzt
aber kein gutes Passwort. Die neue, konfigurierbare Passwort-Policy aus `main` (#189)
greift hier sinnvoll ineinander.

### F6 (Info): Fehlerverhalten beim Streaming-Download

Schlägt die Tag-Prüfung mitten im Download fehl, sind die HTTP-Header (inkl.
`Content-Length` und Status 200) bereits gesendet; der Client erhält einen abgebrochenen
Body. Bereits ausgelieferter Klartext früherer Chunks bleibt ausgeliefert – das ist bei
Chunk-weiser AEAD-Streaming-Entschlüsselung unvermeidlich und in Ordnung, solange Clients
den Abbruch erkennen (tun sie über die Längendifferenz). Wichtig und korrekt umgesetzt:
Es wird **nie unauthentifizierter Klartext** ausgegeben – jeder Chunk wird erst nach
erfolgreicher `final()`-Prüfung gepusht.

### F7 (Niedrig): Kleinere Beobachtungen

- `ShareDTO` exponiert `encrypted` öffentlich – nötig fürs UI, verrät einem
  unauthentifizierten Besucher lediglich, dass es sich lohnt, das Passwort anzugreifen.
  Geringfügig.
- Passwort-Änderung/-Entfernung für verschlüsselte Shares wird serverseitig sauber
  blockiert (`updateShare`), inklusive des `removePassword`-Pfads – nicht nur im UI.
- Die Preview-Sperre existiert nur im Frontend; der Backend-Endpunkt liefert mit
  `download=false` weiterhin inline (mit `CSP: sandbox`). Da der Inhalt ohnehin
  entschlüsselt ausgeliefert wird, ist das keine Sicherheitslücke, nur eine
  UI/Backend-Asymmetrie.
- Reverse Shares: Ein anonymer Uploader kann einen verschlüsselten Share erzeugen, dessen
  Passwort der Reverse-Share-Ersteller nicht kennt – kein Sicherheitsproblem, aber ein
  möglicher Support-Fall.

## 4. Gesamturteil

Die Kryptographie ist **fachlich korrekt und überdurchschnittlich sorgfältig**
implementiert: richtiger AEAD-Modus, starke und gepinnte KDF, saubere Salt- und
Domänentrennung, frische Nonces, durchdachte AAD-Bindung gegen strukturelle Manipulation,
einheitliche Fehlerpfade ohne Orakel, konsequentes Abschalten inkompatibler Features auch
serverseitig. Es gibt **keinen Befund, der die Vertraulichkeit der ruhenden Daten
bricht**.

Handlungsbedarf besteht vor allem bei **F1** (fehlende Chunk-Längen-Validierung →
Datenverlust-Risiko bei Chunk-Size-Änderungen, vom Server unbemerkt) und als Härtung bei
**F2** (Cookie-Attribute und Ablauf des gewrappten Schlüssels).
