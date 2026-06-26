# Libre Key Companion
<img align="right" src="logo.svg">
**An open-source, manufacturer-agnostic manager for hardware security keys on Android.**

Libre Key Companion talks to FIDO2/CTAP2, OATH, Token2, OpenPGP and PIV keys over
**NFC** and **USB-C**, from a single app. It is provided by Token2 Sàrl and the
contributors.

> ⚠️ **Status: beta (v0.9.x).** The read and management features below work and have
> been exercised on real hardware, but this is pre-1.0 software. Some operations
> consume retry counters on your key — read the [Safety](#safety) section before
> using PIN features.

---

## Table of contents

- [What it does](#what-it-does)
- [Feature matrix](#feature-matrix)
- [Screens](#screens)
- [Transport model (NFC & USB)](#transport-model-nfc--usb)
- [FIDO Metadata Service (MDS)](#fido-metadata-service-mds)
- [Building](#building)
- [Installing & running](#installing--running)
- [Supported & tested hardware](#supported--tested-hardware)
- [Safety](#safety)
- [How correctness is verified](#how-correctness-is-verified)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## What it does

A single app to inspect and manage the credentials and applets on a hardware
security key, regardless of who made it. Tap a key to NFC or plug it into USB-C and
the app reads what's on it: FIDO2 passkeys, OATH/Token2 one-time-password secrets,
and the status of the OpenPGP and PIV applets. Where it's safe to do so, it also
lets you manage those credentials.

It is **manufacturer-agnostic**: it speaks the standard protocols (CTAP2, YKOATH,
OpenPGP Card, PIV/NIST SP 800-73) plus the Token2 on-device OTP protocol, so it
works across keys from different vendors rather than being locked to one brand.

---

## Feature matrix

| Area | State | What you can do |
|---|---|---|
| **FIDO2 / CTAP2 management** | ✅ Working (NFC + USB) | Read authenticator info, set / change the PIN, toggle `alwaysUV`, list and delete passkeys (with per-passkey details), enroll / rename / remove fingerprints on bio keys. |
| **OATH (TOTP / HOTP)** | ✅ Working (NFC + USB) | List credentials with live TOTP codes, add via QR scan or `otpauth://` URI, delete. Standard YKOATH applet. |
| **Token2 on-device OTP** | ✅ Working (NFC + USB) | List / add / delete TOTP & HOTP entries stored on Token2 FIDO keys. |
| **FIDO MDS lookup** | ✅ Working | Matches a key's AAGUID against the FIDO Alliance Metadata Service to show the device's real name, certification level (e.g. *FIDO Certified L2*) and icon. Ships with bundled data, updatable in-app. |
| **OpenPGP card** | 🔍 Read-only | Per-slot key existence (Signature / Decryption / Authentication), algorithm & size, generation date, fingerprint, PW1/PW3 retry counters, card serial, cardholder, URL. |
| **PIV** | 🔍 Read-only | Per-slot (9A / 9C / 9D / 9E) X.509 certificate details: subject, issuer, key type & size, validity, serial, SHA-256 fingerprint; PIN/PUK retry counts; card GUID. |

The OTP tab **auto-detects** which applet a key uses (Token2 vs OATH) and routes
list/add/delete accordingly, so one tab serves both.

**Not implemented** (intentionally — these are security-critical write/crypto
operations that belong behind careful, hardware-tested work): OpenPGP key
generation / import / signing / decryption, PIV `GENERAL AUTHENTICATE` /
key generation / certificate import, and OpenPGP/PIV PIN changes. The OpenPGP and
PIV applets are **read-only** today.

**This app has no sign-in / credential-provider features.** It does **not** register
as an Android credential provider or autofill service, and it does not perform
WebAuthn/FIDO2 authentication (`getAssertion`) to log you into websites or apps. It
is purely a *management* tool for what's stored on the key. For **FIDO2 sign-in**
(acting as a passkey/credential provider to other apps), use a dedicated CTAP2
credential-provider app such as [Authnkey](https://github.com/mimi89999/Authnkey).

---

## Screens

- **Info** — an overview card for a tapped/plugged key: which applets are present,
  the FIDO2 device (name + certification + icon from MDS), and tappable rows that
  open full detail dialogs for PIV and OpenPGP.
- **OTP** — TOTP/HOTP credentials with live codes and a countdown; add (QR or paste)
  and delete. Serves both OATH and Token2 keys.
- **FIDO2** — authenticator info, PIN management, `alwaysUV`, passkey list/details/
  delete, and fingerprint enrollment for bio keys.

---

## Transport model (NFC & USB)

Hardware keys expose different applets over different physical interfaces, and the
app routes each operation to the right one:

- **NFC (IsoDep):** all applets are reachable over a single ISO-DEP channel. Tap and
  hold the key to the phone when prompted.
- **USB-C:**
  - **OATH, Token2 OTP, OpenPGP, PIV** use the key's **CCID** smart-card interface.
  - **FIDO2** uses **CTAPHID** on the key's **HID** interface — the CCID interface
    rejects FIDO (`SW 6A81`). The app finds the FIDO HID interface by report-
    descriptor match, falling back to an active `CTAPHID_INIT` probe, then to the
    first usable HID interface.

USB attachment is handled via `USB_DEVICE_ATTACHED` + a runtime permission prompt.
The app filters for the CCID device class plus specific vendor IDs (so FIDO-only
keys with no CCID interface are still recognized).

A built-in **USB diagnostics** screen (overflow menu, or long-press the toolbar)
dumps the interface/endpoint layout and a live CTAPHID probe — useful when a new
key doesn't behave, and exactly the data needed to file a good bug report.

---

## FIDO Metadata Service (MDS)

The app can show a FIDO2 key's friendly name, certification level and icon by
matching its **AAGUID** against the
[FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/).

- **Bundled data:** the APK ships with a metadata set (`res/raw/mds_bundled.json`)
  so lookups work offline out of the box.
- **In-app update:** *About → Update metadata* downloads the full live MDS BLOB from
  `https://mds3.fidoalliance.org/` (free, no token) and caches it on the device.
- **Format:** a flat JSON array of `{ aaguid, description, icon, status }` objects.
  The loader also accepts the raw FIDO MDS3 BLOB (JWT) and the official
  `{entries:[…]}` JSON, auto-detecting the shape.

### Regenerating the bundled set

`tools/generate_mds_bundle.py` downloads the live BLOB and emits the flat-array
format the app reads:

```bash
# Full set, with icons
python3 tools/generate_mds_bundle.py --out app/src/main/res/raw/mds_bundled.json

# Names + certification only (smaller, no icons)
python3 tools/generate_mds_bundle.py --no-icons --out app/src/main/res/raw/mds_bundled.json

# Only keys whose name matches (e.g. to keep the bundle small)
python3 tools/generate_mds_bundle.py --filter yubico token2 --out app/src/main/res/raw/mds_bundled.json
```

> The script reads the BLOB for display data only; it does **not** verify the BLOB's
> signature. That's fine for showing names/icons, but don't treat it as an
> attestation-trust decision.

---

## Building

### Requirements

- **JDK 17** (Android Studio bundles a suitable JBR)
- **Android SDK** with API 34 (`compileSdk = 34`)
- Gradle wrapper is included (Gradle 8.9) — no separate Gradle install needed

### Toolchain versions

| Component | Version |
|---|---|
| Android Gradle Plugin | 8.5.2 |
| Kotlin | 2.0.20 |
| `compileSdk` / `targetSdk` | 34 |
| `minSdk` | 26 (USB Host + modern NFC reader mode) |

### Build (Linux / macOS)

```bash
git clone https://github.com/<your-org>/libre-key-companion.git
cd libre-key-companion
./gradlew clean assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

### Build (Windows / PowerShell)

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"   # adjust to your install
.\gradlew.bat clean assembleDebug
```

> **Always include `clean`** when you've changed resources, the manifest, themes, or
> icons — Android's resource cache can otherwise serve stale resources and make a
> change look like it didn't take.

### Release build

Configure your signing config in `app/build.gradle.kts` (or via
`~/.gradle/gradle.properties`) and run `./gradlew assembleRelease`.

---

## Installing & running

1. Build the APK (above) or grab one from the Releases page.
2. Install it: `adb install -r app/build/outputs/apk/debug/app-debug.apk`, or copy
   the APK to the phone and open it (enable "install unknown apps" for your file
   manager).
3. Launch the app, then **tap a key to the phone's NFC reader** or **plug it into
   USB-C**. Grant the USB permission prompt when it appears.

> The app version is shown in the toolbar. When sideloading manually, make sure each
> new build has a higher `versionCode` or Android may silently skip the install as
> "no update" — the in-toolbar version lets you confirm which build is actually
> running.

---

## Supported & tested hardware

The app targets standards (CTAP2, YKOATH, OpenPGP Card, PIV) plus the Token2 OTP
protocol, so it is not limited to the keys below — but these are what's been
exercised on real devices:

| Key | NFC | USB | Notes |
|---|---|---|---|
| **Token2** FIDO keys (NFC + USB) | ✅ | ✅ | OTP, FIDO2 management, OpenPGP/PIV status. |
| **Token2 Bio3** | ✅ | ✅ | Fingerprint enrollment verified (enroll requires USB). |
| **Pico-FIDO** | ✅ | ✅ | FIDO2 over USB works after a stale-buffer drain on INIT. OATH OTP works. |
| **YubiKey 5** | ✅ | — | Works over NFC. USB is not yet supported for this key. |

Other CTAP2/YKOATH/PIV/OpenPGP keys are expected to work but are unverified — please
report results.

---

## Safety

Hardware keys enforce retry limits. **Some operations are destructive if repeated
with the wrong secret:**

- **FIDO PIN:** entering the wrong FIDO2 PIN consumes the retry counter. Exhausting
  it **locks the key and wipes its passkeys.** Test PIN features on a disposable key
  first.
- **OpenPGP / PIV PINs:** the app *reads* PW1/PW3 and PIN/PUK retry counters
  non-destructively (it never submits a guess just to read the count). It does not
  currently change these PINs.
- **Fingerprint enrollment** requires holding the key still on USB through a
  multi-touch session.

When in doubt, use a spare key you don't mind resetting.

---

## How correctness is verified

Security-sensitive logic is checked by **executing it against published
specification test vectors**, not by inspection. The repository's parsers and
crypto are validated against:

- **OATH** — all RFC 4226 (HOTP) and RFC 6238 (TOTP) test vectors.
- **CTAP2 PIN/UV** — the PIN/UV auth protocol crypto against published CTAP 2.1
  vectors; CTAPHID framing against the spec.
- **Token2** — OTP codec and the ECDH-P256 / AES-CBC seed crypto against known
  vectors.
- **PIV** — the X.509/DER certificate parser against real certificates generated
  with OpenSSL (RSA-2048/4096, EC P-256/P-384), every field cross-checked.
- **OpenPGP** — the Application-Related-Data parser against a spec-accurate object
  (key existence, algorithm attributes, retry counters).

> Caveat: parsing and crypto are verified by execution, but **on-card behavior, USB
> transport, and per-vendor quirks can only be confirmed on real hardware.** Treat
> anything not in the tested-hardware table as unverified.

---

## Project layout

```
app/src/main/java/com/token2/lkcompanion/
├── transport/    ISO-7816 APDUs, NFC (IsoDep) & USB CCID transports
├── oath/         YKOATH applet + RFC 4226/6238 core
├── oathui/       OATH repository & list adapter
├── token2/       Token2 OTP codec, ECDH/AES crypto, HID transport
├── token2ui/     Token2 repository, adapter, add-entry dialog
├── fido/         FIDO applet, MDS repository
│   └── ctap/     CTAP2 client, CBOR, PIN/UV protocol, CTAPHID/APDU wires
├── fidoui/       FIDO repository, passkey & fingerprint adapters
├── openpgp/      OpenPGP card applet (read-only) + BER-TLV
├── piv/          PIV applet (read-only) + X.509/DER parser
└── ui/           MainActivity, status cards, dialogs

tools/            generate_mds_bundle.py (MDS bundle generator)
app/src/main/res/raw/mds_bundled.json   bundled FIDO metadata
```

~6,300 lines of Kotlin, no Jetpack Compose (Views/XML).

---

## Troubleshooting

**A menu/icon/theme change doesn't appear.** Rebuild with `clean` — Android caches
resources.

**A sideloaded build seems unchanged.** Bump `versionCode`; Android skips installs it
considers "no update." The toolbar shows the running version.

**FIDO2 over USB shows nothing for a particular key.** Open **USB diagnostics**
(overflow menu or long-press the toolbar) and check the interface/endpoint dump and
CTAPHID probe. FIDO keys use **interrupt** endpoints; the app drives them with
`UsbRequest` for stacks where `bulkTransfer` on an interrupt endpoint is unreliable.
USB support varies by key — some keys work over NFC only for now. Include the
diagnostic output in any bug report.

**Key blinks once and nothing happens (FIDO-only keys).** These have no CCID
interface; make sure the vendor ID is covered by `res/xml/usb_device_filter.xml`.

**`adb` over cable is blocked because the key occupies the USB port.** Use wireless
ADB, or test NFC.

**MDS shows the raw AAGUID instead of a name.** That key isn't in the bundled set —
run *About → Update metadata*, or regenerate the bundle (see
[FIDO Metadata Service](#fido-metadata-service-mds)).

---

## Roadmap

- OpenPGP: richer status, then (carefully, hardware-tested) PIN verify and crypto.
- PIV: handle compressed (gzipped) slot certificates; PIN verify.
- MDS: optional signature verification of the BLOB.
- Broader hardware verification across more vendors.

---

## Contributing

Contributions are welcome. Please:

- Keep security-sensitive logic **verifiable against spec test vectors**, and add or
  update a vector-based check when you touch crypto or parsers.
- Note which **real hardware** you tested on in the PR.
- For transport/USB changes, include **USB diagnostics** output for the affected
  key(s).
- Don't add destructive operations without retry-counter safeguards and clear
  warnings.

Open an issue for bugs or new-key reports — the USB diagnostics dump and the key's
exact model/firmware are the most useful things to include.

---

## License

See [LICENSE](LICENSE). <!-- Add a LICENSE file (e.g. Apache-2.0 or GPL-3.0) and name it here. -->

---

## Acknowledgements

- The [FIDO Alliance](https://fidoalliance.org/) Metadata Service for the public
  authenticator metadata.
- The CTAP2, OATH (RFC 4226/6238), OpenPGP Card and NIST SP 800-73 (PIV)
  specifications.
- [Authnkey](https://github.com/mimi89999/Authnkey) for FIDO2 credential-provider
  sign-in (a complementary app).

*Libre Key Companion is provided by Token2 Sàrl and the contributors.*
