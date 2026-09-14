package com.token2.lkcompanion.token2

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * Token2 on-device OTP client (§6/§8). Works over either:
 *   - PC/SC over NFC: pass a [SmartCardTransport] (the app's NfcTransport).
 *   - USB-HID: pass a [Token2HidTransport].
 * Both are funneled through a single [send] lambda so the client logic is shared.
 *
 * The management applet AID (NFC/PC-SC) is F0 00 00 01 4F 74 70 01.
 *
 * Implemented: READ_CONFIG feature detection, GET_ECDH_PUBKEY, enumerate (paged),
 * read-one, write/update (encrypted), delete (encrypted), erase-all.
 *
 * Deliberately guarded: SET_DEVICE_TYPE includes the anti-brick check from §6.8 —
 * it refuses any mask that would disable every interface. (Read the hardware-safety
 * warning in the protocol doc before ever calling it.)
 */
class Token2Client private constructor(
    private val send: (apdu: ByteArray, buttonWait: Boolean) -> ByteArray,
    private val isNfc: Boolean,
    // Raw transceive that returns (data, sw) WITHOUT throwing — PIN commands need
    // to inspect status words (6982/6983/6A81/6A86) rather than have them thrown.
    private val sendRaw: ((apdu: ByteArray) -> Pair<ByteArray, Int>)? = null,
) {
    // Set after a successful verifyOtpPin: on a protected key, enumerate/read
    // responses come back encrypted (IV || EncData || Auth) under these keys and
    // must be decrypted before parsing.
    private var pinSession: Token2PinCrypto.SessionKeys? = null
    companion object {
        val MGMT_AID = byteArrayOf(0xF0.toByte(), 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01)
        val FIDO_AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)

        // SET_DEVICE_TYPE disable-mask bits (§6.8): a set bit disables that interface.
        const val DEV_FIDO = 0x01
        const val DEV_KEYBOARD = 0x02
        const val DEV_CCID = 0x04

        // CLA INS P1 P2 per §6
        private val WRITE_HOTP_SEED = intArrayOf(0x80, 0xC5, 0x00, 0x00)
        private val GET_ECDH_PUBKEY = intArrayOf(0x80, 0xC5, 0x01, 0x00)
        private val READ_CONFIG = intArrayOf(0x80, 0xC5, 0x02, 0x00)
        private val SET_DEVICE_TYPE = intArrayOf(0x80, 0xC5, 0x02, 0x01)
        private val ENABLE_TOTP = intArrayOf(0x80, 0xC5, 0x02, 0x05)
        private val ENUM_CODES = intArrayOf(0x80, 0xC5, 0x05, 0x00)
        private val ENUM_CODES_CONTINUE = intArrayOf(0x80, 0xC5, 0x05, 0x01)
        private val WRITE_SEED = intArrayOf(0x80, 0xC5, 0x05, 0x02)
        private val GET_INFO = intArrayOf(0x80, 0x33, 0x00, 0x00)

        // --- OTP PIN / privacy protection (R3.4 / manual V1.2) ---
        private val READ_OTP_PIN_FLAG = intArrayOf(0x80, 0xC5, 0x05, 0x04)
        private val SET_OTP_PIN = intArrayOf(0x80, 0xC5, 0x05, 0x05)
        private val VERIFY_OTP_PIN = intArrayOf(0x80, 0xC5, 0x05, 0x06)
        private val CHANGE_OTP_PIN = intArrayOf(0x80, 0xC5, 0x05, 0x08)
        private val READ_AGREEMENT_PUBKEY = intArrayOf(0x80, 0xC5, 0x05, 0x09)
        /** Lc for the short PIN-flag read (status only). */
        private const val PIN_FLAG_LC_BASE = 0x04
        /** Lc for the PIN-flag read that also returns the verify challenge (IV||EncRand). */
        private const val PIN_FLAG_LC_CHALLENGE = 0x29
        /** Lc for the "prime" flag read done before the agreement handshake. */
        private const val PIN_FLAG_LC_PRIME = 0x09
        /** Bounded fingerprint capture-poll budget (each poll is one round trip). */
        private const val FP_MAX_POLLS = 600

        /** Build over NFC/PC-SC; selects the management applet up front. */
        fun overNfc(transport: SmartCardTransport): Token2Client {
            transport.selectApplet(MGMT_AID)
            return Token2Client(
                send = { apdu, _ ->
                    val r = transport.transceive(apdu)
                    if (!r.isSuccess) mapStatus(r.sw)
                    r.data
                },
                isNfc = true,
                sendRaw = { apdu ->
                    val r = transport.transceive(apdu)
                    Pair(r.data, r.sw)
                },
            )
        }

        /** Build over USB-HID. (PIN commands are unsupported over HID; sendRaw is null.) */
        fun overHid(hid: Token2HidTransport): Token2Client =
            Token2Client(
                send = { apdu, buttonWait -> hid.sendCommand(apdu, buttonWait) },
                isNfc = false,
            )

        /**
         * Bare instance for unit-testing pure helpers (e.g. the fingerprint
         * capture-poll loop). Transports are stubbed and never touched by the
         * helpers under test. Not for production use.
         */
        internal fun overHidForTest(): Token2Client =
            Token2Client(
                send = { _, _ -> ByteArray(0) },
                isNfc = false,
            )

        private fun mapStatus(sw: Int): Nothing = when (sw) {
            0x6A80, 0x6A83 -> throw Token2Exception.EntryNotFound
            0x6A84 -> throw Token2Exception.NotEnoughSpace
            0x6FF9 -> throw Token2Exception.ButtonPressRequired
            // 6982 = security status not satisfied. On a PIN-protected key, an
            // ordinary read (ENUM_CODES) returns this until the PIN window is
            // opened — surface it as PinNotVerified so the UI can prompt to unlock.
            0x6982 -> throw Token2Exception.PinNotVerified
            0x6983 -> throw Token2Exception.PinBlocked
            // NOTE: 6A86 is "incorrect P1/P2 / instruction not supported on this
            // model". The spec only ties it to the HOTP-over-HID *config* commands;
            // do NOT relabel it as a HID error on other commands. Surface the SW.
            else -> throw Token2Exception.BadStatus(sw)
        }
    }

    data class DeviceInfo(
        val totpSupported: Boolean,
        val hotpSupported: Boolean,
        val nfcSupported: Boolean,
        val ccidSupported: Boolean,
        val fingerprintPresent: Boolean,
        val fidoHasPin: Boolean,
        val buttonHotpConfigured: Boolean,
        val fidoVersion: String,
        // --- current interface state (byte 0 / transfer-type, §6.9) ---
        // These say which USB interfaces are *disabled right now*, independent of
        // whether the model *supports* them (that's the *Supported flags above).
        // A set bit in byte 0 means "this interface is currently turned off".
        val fidoDisabled: Boolean,
        val keyboardHidDisabled: Boolean,
        val ccidDisabled: Boolean,
        /** §1.11 ext byte bit 8: the key can require a fingerprint for OTP generation. */
        val otpFingerprintProtectSupported: Boolean = false,
        /** §1.11 ext byte bit 7: OTP generation currently requires fingerprint verification. */
        val otpFingerprintRequired: Boolean = false,
        val raw: ByteArray,
    ) {
        /** True when the config blob actually carried byte 1 (the capability byte),
         *  as opposed to a short CCID/NFC stub that only returned byte 0. When
         *  false, the *Supported flags derived from byte 1/9 are not trustworthy. */
        val hasConfigByte: Boolean get() = raw.size >= 2
    }

    // Extended-length APDU helper (§3): everything but PC/SC SELECT uses extended Lc.
    private fun apduExt(cmd: IntArray, data: ByteArray): ByteArray {
        val out = ArrayList<Byte>(5 + data.size)
        out.add(cmd[0].toByte()); out.add(cmd[1].toByte())
        out.add(cmd[2].toByte()); out.add(cmd[3].toByte())
        out.add(0x00)                                  // extended Lc marker
        out.add(((data.size ushr 8) and 0xFF).toByte())
        out.add((data.size and 0xFF).toByte())
        data.forEach { out.add(it) }
        return out.toByteArray()
    }

    /** §6.9 feature detection. Call first. */
    fun readConfig(numBytes: Int = 10): DeviceInfo {
        // §1.11: READ_CONFIG is an ISO case-2 command — 4-byte header + a single
        // Le byte (number of bytes wanted), NO Lc/data. Building it with an
        // extended-Lc *data* body makes the card answer 61 01 (only 1 byte
        // available) over PC/SC — which is why earlier only byte 0 came back and
        // every capability read as "unsupported". keyroost documents the same
        // fix. A plain Le asks for the whole block.
        val le = numBytes.coerceIn(10, 64)
        val apdu = byteArrayOf(
            READ_CONFIG[0].toByte(), READ_CONFIG[1].toByte(),
            READ_CONFIG[2].toByte(), READ_CONFIG[3].toByte(),
            le.toByte(),
        )
        val resp = send(apdu, false)
        if (resp.isEmpty()) throw Token2Exception.BadStatus(0x6A80)
        // The interface-state bits (byte 0) are the only hard requirement; some
        // firmware returns just byte 0 over CCID/NFC while USB-HID returns the
        // full block. Read whatever came back, defaulting absent fields to 0, but
        // keep `raw` at its true length so hasConfigByte can tell a real value
        // from zero-padding (matching keyroost's raw_len handling).
        fun at(i: Int): Int = if (i < resp.size) resp[i].toInt() and 0xFF else 0
        val iface = at(0)                     // byte 0: transfer-type / interface state
        val cfg = at(1)                       // byte 1: capability flags
        val ext = at(9)                       // byte 9: extension flags
        val fido = "${at(6)}.${at(7)}.${at(8)}"
        return DeviceInfo(
            totpSupported = ext and 0x01 != 0,
            hotpSupported = cfg and 0x04 != 0,
            nfcSupported = cfg and 0x10 != 0,
            ccidSupported = ext and 0x10 != 0,
            fingerprintPresent = cfg and 0x08 != 0,
            fidoHasPin = cfg and 0x02 != 0,
            buttonHotpConfigured = cfg and 0x80 != 0,
            fidoVersion = fido,
            // byte 0: bit1 FIDO off, bit2 keyboard-HID off, bit3 CCID off (§6.9).
            fidoDisabled = iface and 0x01 != 0,
            keyboardHidDisabled = iface and 0x02 != 0,
            ccidDisabled = iface and 0x04 != 0,
            // byte 9 (ext): bit7 = fingerprint currently required for OTP,
            // bit8 = fingerprint-protected OTP supported (§1.11 item 5).
            otpFingerprintRequired = ext and 0x40 != 0,
            otpFingerprintProtectSupported = ext and 0x80 != 0,
            raw = resp,
        )
    }

    fun getEcdhPubkey(): ByteArray {
        val pk = send(apduExt(GET_ECDH_PUBKEY, ByteArray(0)), false)
        require(pk.size == 64) { "expected 64-byte pubkey, got ${pk.size}" }
        return pk
    }

    /** Enumerate all entries, following ENUM_CODES_CONTINUE paging (§6.1). */
    fun enumerate(timestampSeconds: Long): List<Token2Codec.Entry> {
        val all = ArrayList<Token2Codec.Entry>()
        var resp = maybeDecryptPage(send(apduExt(ENUM_CODES, Token2Codec.serializeReadAll(timestampSeconds)), false))
        try {
            while (true) {
                val (entries, more) = Token2Codec.parseEnumPage(resp, fullDecode = false)
                all.addAll(entries)
                if (!more) break
                resp = maybeDecryptPage(send(apduExt(ENUM_CODES_CONTINUE, Token2Codec.serializeContinue(timestampSeconds)), false))
            }
        } catch (e: Token2Codec.ParseException) {
            // If we couldn't parse and no PIN session is active, the key likely
            // returned an encrypted page from a still-open window we don't hold
            // keys for (e.g. after a local lock over a persistent USB link).
            // Surface as needs-verify instead of crashing on garbage.
            if (pinSession == null) throw Token2Exception.PinNotVerified
            throw e
        }
        return all
    }

    /**
     * On a PIN-protected key (after verifyOtpPin), enumerate/read responses come
     * back as IV(16) || EncData || Auth(16) under the session keys. Decrypt and
     * MAC-check them; otherwise pass through unchanged.
     */
    private fun maybeDecryptPage(data: ByteArray): ByteArray {
        val keys = pinSession ?: return data
        if (data.size < 48) return data          // too short to be an enc page
        val iv = data.copyOfRange(0, 16)
        val enc = data.copyOfRange(16, data.size - 16)
        val auth = data.copyOfRange(data.size - 16, data.size)
        if (!Token2PinCrypto.verifyAuthTag(keys.mac, enc, auth))
            throw Token2Exception.BadStatus(0x6982)   // MAC mismatch -> treat as not-verified
        return Token2PinCrypto.sessionDecrypt(keys.enc, iv, enc)
    }

    /** Read one entry, always including the code (waits for button on HID). */
    fun readEntry(timestampSeconds: Long, app: String, acct: String): Token2Codec.Entry {
        val resp = send(apduExt(ENUM_CODES,
            Token2Codec.serializeReadOne(timestampSeconds, app, acct)), true)
        return Token2Codec.parseEnumPage(resp, fullDecode = true).first.first()
    }

    /**
     * Seal a write cleartext, choosing the format by PIN state (matches the
     * reference `seal`): if a PIN window is open (pinSession set), the device
     * rejects GET_ECDH_PUBKEY with 6A81, so reuse the verified session keys in
     * the authenticated protected-write format; otherwise build the standard
     * ephemeral-ECDH seed blob.
     */
    private fun sealWrite(cleartext: ByteArray): ByteArray {
        val keys = pinSession
        return if (keys != null)
            Token2PinCrypto.buildProtectedWriteData(keys, cleartext)
        else
            Token2Crypto.encryptPayload(getEcdhPubkey(), cleartext, Token2Crypto.IV_WRITE_SEED)
    }

    /** Write or update an entry (encrypted, IV-1; protected format when PIN-verified). */
    fun writeEntry(entry: Token2Codec.Entry) {
        val cleartext = Token2Codec.serializeWriteEntry(entry)
        send(apduExt(WRITE_SEED, sealWrite(cleartext)), false)
    }

    /** Delete an entry (encrypted empty-seed write, IV-1; protected when PIN-verified). */
    fun deleteEntry(app: String, acct: String) {
        val cleartext = Token2Codec.serializeDeleteEntry(app, acct)
        send(apduExt(WRITE_SEED, sealWrite(cleartext)), false)
    }

    /** Erase all — WRITE_SEED with empty data; requires button on HID (§6.5). */
    fun eraseAll() {
        send(apduExt(WRITE_SEED, ByteArray(0)), true)
    }

    fun enableTotp(enabled: Boolean) {
        send(apduExt(ENABLE_TOTP, byteArrayOf(if (enabled) 0x01 else 0x00)), false)
    }

    /**
     * Enable/disable the key's USB interfaces by *which ones to keep on* — the
     * ergonomic front door to [setDeviceType].
     *
     * `fido` / `keyboard` / `ccid` are the desired ENABLED state of each
     * interface; this builds the §6.8 disable-mask (a set bit disables) from them.
     *
     * Safety: like the keyroost reference tool, this requires **at least two**
     * interfaces to remain enabled. Disabling all three bricks the key; leaving
     * only one is fragile — if that single interface can't be reached (e.g. you
     * keep FIDO only, but this phone talks to the key over CCID/NFC) you'd be
     * locked out with no way to undo it. Two-interface minimum keeps a margin.
     *
     * @throws IllegalArgumentException if fewer than two interfaces would remain.
     */
    fun setInterfaces(fido: Boolean, keyboard: Boolean, ccid: Boolean) {
        val enabledCount = listOf(fido, keyboard, ccid).count { it }
        require(enabledCount >= 2) {
            "at least two interfaces must stay enabled (FIDO / keyboard-HID / CCID); " +
                "reducing to one or zero risks locking you out of the key"
        }
        var disable = 0
        if (!fido) disable = disable or DEV_FIDO
        if (!keyboard) disable = disable or DEV_KEYBOARD
        if (!ccid) disable = disable or DEV_CCID
        setDeviceType(disable)
    }

    /**
     * §6.8 — guarded. The mask is "interfaces to DISABLE" (bit1 FIDO, bit2 keyboard,
     * bit3 CCID). We refuse any mask that would leave zero channels, matching the
     * companion app's anti-brick check. Reads current config first.
     */
    fun setDeviceType(disableMask: Int) {
        // Anti-brick guard based purely on the mask: refuse only a mask that
        // disables all three interfaces at once (0x07). Deriving "which
        // interfaces exist" from the capability bytes is unreliable here because
        // over CCID/NFC some firmware returns only byte 0 (interface state) and
        // no capability byte, which would make every capability read as false.
        require(disableMask and 0x07 != 0x07) {
            "refusing SET_DEVICE_TYPE mask 0x%02X — it would disable every interface (brick risk)"
                .format(disableMask)
        }
        // Short-form Lc (single 0x01) for the 1-byte mask body: 80 C5 02 01 01 <mask>.
        // T=0 contact (CCID) readers reject the extended-Lc (00 hi lo) form with
        // 6700/6A86; short form is valid over CCID, NFC, and USB-HID alike, so it
        // is the universal encoding keyroost uses for this command.
        val apdu = byteArrayOf(
            SET_DEVICE_TYPE[0].toByte(), SET_DEVICE_TYPE[1].toByte(),
            SET_DEVICE_TYPE[2].toByte(), SET_DEVICE_TYPE[3].toByte(),
            0x01, disableMask.toByte(),
        )
        send(apdu, false)
    }

    // ===== OTP PIN (privacy protection) ======================================
    // These run ONLY over CCID/NFC (sendRaw != null). Over USB-HID the OTP applet
    // answers with 6A86, so the client is built without sendRaw for HID and these
    // throw PinTransportUnavailable.

    /** Parsed READ_OTP_PIN_FLAG head, plus the optional verify challenge. */
    data class PinFlag(
        val algId: Int,
        val retriesLeft: Int,
        val pinLen: Int,
        val maxRetries: Int,
        /** §1.12 byte 4 `FpEnable`: fingerprint-protected OTP is switched on. Null if the read was too short. */
        val fpEnable: Boolean?,
        /** (IV, EncRand), present only on the Lc=0x29 read. */
        val challenge: Pair<ByteArray, ByteArray>?,
    ) {
        val isSet: Boolean get() = pinLen > 0
    }

    /**
     * Last-seen fingerprint-protection flag for this connection, refreshed by
     * every PIN-flag read (status / prime / challenge). Lets the repository
     * know, after [verifyOtpPin], whether a §1.20 fingerprint check is also
     * needed before codes can be read.
     */
    @Volatile var fingerprintProtectionEnabled: Boolean? = null
        private set

    private fun raw(apdu: ByteArray): Pair<ByteArray, Int> {
        val fn = sendRaw ?: throw Token2Exception.PinTransportUnavailable
        return fn(apdu)
    }

    /** Map a PIN-command status word to a typed error (or return on success). */
    private fun checkPin(sw: Int, ctx: String = "") {
        when (sw) {
            0x9000, 0x6100, 0x6101 -> return   // 61xx = more data available (chaining)
            0x6982 -> throw Token2Exception.PinNotVerified
            0x6983 -> throw Token2Exception.PinBlocked
            0x6A81 -> throw Token2Exception.PinWrongState
            0x6A86, 0x6AF8 -> throw Token2Exception.PinUnsupported(sw, ctx)
            else -> {
                // 63xx = verification failed, low nibble often = retries left.
                // Treat as a wrong PIN so the UI re-prompts with the count.
                if ((sw and 0xFF00) == 0x6300) throw Token2Exception.PinNotVerified
                if ((sw and 0xFF00) == 0x6100) return
                throw Token2Exception.BadStatus(sw)
            }
        }
    }

    private fun readPinFlagApdu(lc: Int): ByteArray {
        // The flag read is NOT a bare case-2 command. Per the reference and R3.4
        // device probing, it is `CLA INS P1 P2 len || len*0x00` — the Lc byte
        // followed by a body of `len` placeholder zero bytes. A bodyless read in
        // any form is rejected with the proprietary 6AF8 (which we'd otherwise
        // mislabel as "PIN unsupported"). The applet overwrites the placeholder
        // and returns `len` bytes of flag data.
        val out = ArrayList<Byte>(5 + lc)
        READ_OTP_PIN_FLAG.forEach { out.add(it.toByte()) }
        out.add(lc.toByte())
        repeat(lc) { out.add(0x00) }
        return out.toByteArray()
    }

    private fun parsePinFlag(data: ByteArray): PinFlag {
        fun at(i: Int) = if (i < data.size) data[i].toInt() and 0xFF else 0
        // Fixed head: AlgId, RetriesLeft, PinLen, MaxRetries.
        val flag = PinFlag(
            algId = at(0),
            retriesLeft = at(1),
            pinLen = at(2),
            maxRetries = at(3),
            fpEnable = if (data.size >= 5) at(4) == 0x01 else null,
            challenge = if (data.size >= 41) {
                // On the Lc=0x29 read: IV(16) EncRand(16) starting at offset 9.
                Pair(data.copyOfRange(9, 25), data.copyOfRange(25, 41))
            } else null,
        )
        flag.fpEnable?.let { fingerprintProtectionEnabled = it }
        return flag
    }

    /** READ_OTP_PIN_FLAG status only (Lc=0x04). */
    fun pinStatus(): PinFlag {
        // Use Lc=0x09 (the form the reference's working trace uses) for a reliable
        // full head. The short Lc=0x04 read can come back truncated on some
        // firmware, making a *set* PIN look unset.
        val (data, sw) = raw(readPinFlagApdu(PIN_FLAG_LC_PRIME))
        checkPin(sw, "status-read")
        return parsePinFlag(data)
    }

    /**
     * Establish an authenticated ECDH session. Returns the session keys.
     * Sequence (per reference): a "prime" flag read (Lc=0x09) FIRST — skipping it
     * makes a later SET fail with 6985 — then READ_AGREEMENT_PUBKEY with the host
     * pubkey; response is devPub(64) || sig(132). The P-521 device signature is
     * NOT verified (matches the reference; confidentiality holds, authenticity is
     * not cryptographically checked).
     */
    private fun openPinSession(): Token2PinCrypto.SessionKeys {
        // Prime read.
        val (_, psw) = raw(readPinFlagApdu(PIN_FLAG_LC_PRIME))
        checkPin(psw, "prime-read(0x09)")

        // Two-step handshake: generate the host keypair, send its public X||Y in
        // READ_AGREEMENT_PUBKEY, then derive session keys from the device's
        // returned pubkey using the SAME host private key.
        val hs = Token2PinCrypto.beginHandshake()
        val (resp, sw) = raw(pinApdu(READ_AGREEMENT_PUBKEY, hs.hostPubXy))
        checkPin(sw, "agreement-pubkey")
        if (resp.size < 64) throw Token2Exception.BadStatus(sw)
        val devXy = resp.copyOfRange(0, 64)
        return hs.deriveWith(devXy)
    }

    /** SET_OTP_PIN from the unprotected state. */
    fun setOtpPin(pin: ByteArray) {
        val keys = openPinSession()
        val data = Token2PinCrypto.buildSetPinData(keys, pin)
        val apdu = pinApdu(SET_OTP_PIN, data)
        val (_, sw) = raw(apdu)
        checkPin(sw, "set-pin")
    }

    /**
     * VERIFY_OTP_PIN — opens the read window for this connection.
     * `fpEnable`, when non-null, also sets/clears the fingerprint-protected-OTP
     * flag in the same command via the optional EncConfig block (§1.14 / §1.20).
     */
    fun verifyOtpPin(pin: ByteArray, fpEnable: Boolean? = null) {
        val keys = openPinSession()
        val (data, sw) = raw(readPinFlagApdu(PIN_FLAG_LC_CHALLENGE))
        checkPin(sw, "verify-challenge-read")
        val flag = parsePinFlag(data)
        val ch = flag.challenge ?: throw Token2Exception.BadStatus(sw)
        val rand = Token2PinCrypto.sessionDecryptRaw(keys.enc, ch.first, ch.second)
        if (rand.size != 16) throw Token2Exception.BadStatus(sw)
        val proof = Token2PinCrypto.buildVerifyPinData(keys, pin, rand, fpEnable)
        val (_, vsw) = raw(pinApdu(VERIFY_OTP_PIN, proof))
        // Enabling FP protection with no enrolled fingerprint is refused with
        // 0x6984 ("reference data not usable"). Surface it as a clear "enroll a
        // fingerprint first" rather than a generic wrong-PIN (matches keyroost).
        if (fpEnable == true && vsw == 0x6984) throw Token2Exception.NoFingerprintEnrolled
        checkPin(vsw, "verify-proof")
        if (fpEnable != null) fingerprintProtectionEnabled = fpEnable
        pinSession = keys   // retain for decrypting protected enumerate/read pages
    }

    /**
     * §1.20 fingerprint verification: `80 C5 05 06 01 01` (same header as the
     * PIN-lock command, body 0x01 instead of 0x00). The key waits for a finger
     * on its sensor and answers 9000 once matched; the OTP permissions are then
     * granted for this connection. Anything else is surfaced as
     * [Token2Exception.FingerprintNotVerified] so the UI can ask for a retry.
     * Practically usable over USB-CCID; over NFC the user must keep the key on
     * the phone while touching the sensor.
     */
    fun verifyOtpFingerprint() {
        // A fingerprint unlock still reads codes over the ECDH-encrypted session
        // (the touch authorizes; the session keys still encrypt the enumerate
        // pages). Establish the session first, or the protected pages can't be
        // decrypted. Matches the keyroost reference (verify_fingerprint).
        val keys = openPinSession()

        // Start the capture: 80 C5 05 06 01 01. The device answers 0x9100
        // ("capture in progress"), NOT 0x9000 — then the host polls with
        // 80 11 00 00 00 until 0x9000 (touch captured) or an error. A one-shot
        // read that expects 0x9000 immediately would wrongly fail here.
        val startApdu = byteArrayOf(
            VERIFY_OTP_PIN[0].toByte(), VERIFY_OTP_PIN[1].toByte(),
            VERIFY_OTP_PIN[2].toByte(), VERIFY_OTP_PIN[3].toByte(),
            0x01, 0x01,
        )
        val pollApdu = byteArrayOf(0x80.toByte(), 0x11, 0x00, 0x00, 0x00)

        // Drive the capture-poll state machine over the raw transport, then map
        // the terminal status word. Kept in a pure helper so the 0x9100-poll
        // sequencing is unit-testable without a live ECDH session.
        val terminal = pollFingerprintCapture(
            start = { raw(startApdu).second },
            poll = { raw(pollApdu).second },
        )
        when (terminal) {
            0x9000 -> { /* captured — window open */ }
            // 0x6FFA is the fingerprint counterpart of the button-timeout word:
            // capture failed or the sensor wasn't touched in time.
            0x6FFA -> throw Token2Exception.FingerprintNotVerified(terminal)
            0x6A86, 0x6AF8 -> throw Token2Exception.PinUnsupported(terminal, "fingerprint-verify")
            else -> checkPin(terminal, "fingerprint-verify")   // 6982 = FP protection not enabled, etc.
        }
        pinSession = keys   // retain for decrypting protected enumerate/read pages
    }

    /** CHANGE_OTP_PIN (newPin empty = remove). Requires the current PIN. */
    fun changeOtpPin(currentPin: ByteArray, newPin: ByteArray) {
        val keys = openPinSession()
        // The challenge read primes the change proof, like verify.
        val (data, sw) = raw(readPinFlagApdu(PIN_FLAG_LC_CHALLENGE))
        checkPin(sw)
        val data2 = Token2PinCrypto.buildChangePinData(keys, newPin, currentPin)
        val (_, csw) = raw(pinApdu(CHANGE_OTP_PIN, data2))
        checkPin(csw)
    }

    fun removeOtpPin(currentPin: ByteArray) = changeOtpPin(currentPin, ByteArray(0))

    /**
     * Close the device's read/write verify window: VERIFY header + single 0x00
     * body (80 C5 05 06 01 00), short-form Lc. After this the key returns 6982 to
     * reads until re-verified. Also drops our local session keys.
     */
    fun lockOtpPin() {
        pinSession = null
        val fn = sendRaw ?: return   // only meaningful over CCID/NFC
        val apdu = byteArrayOf(
            VERIFY_OTP_PIN[0].toByte(), VERIFY_OTP_PIN[1].toByte(),
            VERIFY_OTP_PIN[2].toByte(), VERIFY_OTP_PIN[3].toByte(),
            0x01, 0x00,
        )
        try { fn(apdu) } catch (_: Exception) { /* best effort */ }
    }

    /**
     * Pure fingerprint capture-poll loop (manual §1.20 / keyroost reference):
     * send the start APDU, then poll while the device answers 0x9100 ("capture
     * in progress") until it returns a terminal status word (0x9000 on a
     * captured touch, or an error). Bounded by [FP_MAX_POLLS] so a sensor that
     * is never touched cannot spin forever. Some firmware/replay traces answer
     * 0x9000 to the start APDU directly, in which case no poll happens.
     * Returns the terminal SW for the caller to map.
     */
    internal fun pollFingerprintCapture(start: () -> Int, poll: () -> Int): Int {
        var sw = start()
        var polls = 0
        while (sw == 0x9100) {
            if (polls >= FP_MAX_POLLS) return 0x6FFA   // treat as capture timeout
            polls++
            sw = poll()
        }
        return sw
    }

    private fun pinApdu(cmd: IntArray, data: ByteArray): ByteArray {
        // Extended Lc (00 hi lo) — the form the reference build_apdu uses for the
        // SET/VERIFY/CHANGE PIN commands (their data fields exceed the short-form
        // comfort zone and the applet expects extended here).
        require(data.size <= 0xFFFF) { "PIN data field too long" }
        val out = ArrayList<Byte>(7 + data.size)
        cmd.forEach { out.add(it.toByte()) }
        out.add(0x00)
        out.add(((data.size ushr 8) and 0xFF).toByte())
        out.add((data.size and 0xFF).toByte())
        data.forEach { out.add(it) }
        return out.toByteArray()
    }
}
