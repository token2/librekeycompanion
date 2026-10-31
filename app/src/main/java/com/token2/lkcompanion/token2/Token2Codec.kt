package com.token2.lkcompanion.token2

import java.io.ByteArrayOutputStream

/**
 * Token2 on-device OTP — data model + codec layer (pure functions, no I/O).
 *
 * Implements the entry record format and command payload serialization from the
 * Token2 OTP SDK protocol (docs/Token2-OTP-SDK-Protocol.md in token2/token2-otp-cli,
 * MIT). The variable-length entry parser was validated against the §10.1 worked
 * trace before this port — see Token2CodecTest.
 *
 * NOTE on the spec's §10.1 hex example: its leading byte is printed `00` but
 * annotated as a TOTP entry (type 01). The normative prose (§6.1, §11) is the
 * authority and is what this code follows: bit 7 of the first byte is the
 * partial-page flag; bits 0–6 are the first entry's `type`; and the trailing
 * OTP-code field is present ONLY when `type == TOTP && btn_flag == not_required`.
 */
object Token2Codec {

    const val TYPE_HOTP = 0x00
    const val TYPE_TOTP = 0x01
    const val ALG_SHA1 = 0xC1
    const val ALG_SHA256 = 0xC2

    data class Entry(
        val type: Int,
        val algorithm: Int,
        val timestep: Int,
        val codeLength: Int,
        val buttonRequired: Boolean,
        val appName: String,
        val accountName: String,
        val otpCode: String? = null,
        val seed: ByteArray? = null,   // only set on writes; never returned by device
    ) {
        val isTotp: Boolean get() = type == TYPE_TOTP
        val key: Pair<String, String> get() = appName to accountName

        override fun equals(other: Any?): Boolean =
            other is Entry && type == other.type && appName == other.appName &&
            accountName == other.accountName
        override fun hashCode(): Int = 31 * appName.hashCode() + accountName.hashCode()
    }

    /** Thrown when a wire entry record can't be framed (desync / truncation). */
    class ParseException(msg: String) : Exception(msg)

    /**
     * Parse one ENUM_CODES response page. The first byte carries the partial-page
     * flag in bit 7; the remaining bits 0–6 are the first entry's type. Returns
     * the entries plus whether more pages follow (issue ENUM_CODES_CONTINUE).
     *
     * @param fullDecode force-include the OTP-code tail (READ_ONE always includes it).
     */
    /**
     * Parse a READ_ONE response. Unlike READ_ALL pages, the READ_ONE response has
     * NO "more pages" flag in byte 0 — byte 0 is the entry's type directly. This
     * mirrors the desktop reference `parse_entries(d, full=true)` exactly (no
     * bit7 masking). Applying the page-mask logic here corrupts the offsets and
     * throws "toIndex > size". Always full-decodes (the code tail is present).
     */
    fun parseReadOne(data: ByteArray): Entry {
        val entries = parseEntryRecords(data, full = true)
        return entries.lastOrNull() ?: throw ParseException("empty READ_ONE response")
    }

    fun parseEnumPage(data: ByteArray, fullDecode: Boolean = false): Pair<List<Entry>, Boolean> {
        if (data.isEmpty()) return emptyList<Entry>() to false
        val morePages = (data[0].toInt() and 0x80) != 0
        // READ_ALL pages carry a "more pages" flag in bit7 of byte 0; clear it
        // before parsing the (type) field. READ_ONE has no such flag — it uses
        // parseReadOne/parseEntryRecords directly, without this masking.
        val stream = data.copyOf()
        stream[0] = (stream[0].toInt() and 0x7F).toByte()
        return parseEntryRecords(stream, full = fullDecode) to morePages
    }

    /**
     * Parse a sequence of entry records (no page flag). Field layout, per the
     * device protocol and the desktop reference `parse_entries`:
     *   type(1) algo(1) timestep(2 BE) codeLen(1) button(1) appLen(1) app(appLen)
     *   acctLen(1) acct(acctLen) [ codeLen(1) code(codeLen) ]?
     * The code tail is present when `full` (READ_ONE) or for a TOTP without button.
     */
    private fun parseEntryRecords(stream: ByteArray, full: Boolean): List<Entry> {
        val entries = ArrayList<Entry>()
        var i = 0
        while (i < stream.size) {
            if (i + 7 > stream.size) break   // trailing padding shorter than a header
            val type = stream[i].toInt() and 0xFF; i++
            val algo = stream[i].toInt() and 0xFF; i++
            val timestep = ((stream[i].toInt() and 0xFF) shl 8) or (stream[i + 1].toInt() and 0xFF); i += 2
            val codeLen = stream[i].toInt() and 0xFF; i++
            val btn = stream[i].toInt() and 0xFF; i++
            val appLen = stream[i].toInt() and 0xFF; i++
            if (i + appLen > stream.size) throw ParseException("app_name overruns page")
            val app = String(stream, i, appLen, Charsets.US_ASCII); i += appLen
            if (i >= stream.size) throw ParseException("missing account_name_len")
            val acctLen = stream[i].toInt() and 0xFF; i++
            if (i + acctLen > stream.size) throw ParseException("account_name overruns page")
            val acct = String(stream, i, acctLen, Charsets.US_ASCII); i += acctLen

            var code: String? = null
            val hasTail = full || (type == TYPE_TOTP && btn == 0x00)
            if (hasTail) {
                if (i >= stream.size) throw ParseException("missing otp_code_len")
                val codeStrLen = stream[i].toInt() and 0xFF; i++
                if (i + codeStrLen > stream.size) throw ParseException("otp_code overruns page")
                code = String(stream, i, codeStrLen, Charsets.US_ASCII); i += codeStrLen
            }
            entries.add(Entry(type, algo, timestep, codeLen, btn != 0, app, acct, code))
        }
        return entries
    }

    /** Build the cleartext write payload (§6.3) — encrypted before sending. */
    fun serializeWriteEntry(e: Entry): ByteArray {
        val seed = e.seed ?: ByteArray(0)
        validateWrite(e, seed)
        return ByteArrayOutputStream().apply {
            write(e.type)
            write(e.algorithm)
            write((e.timestep ushr 8) and 0xFF); write(e.timestep and 0xFF)
            write(e.codeLength)
            write(if (e.buttonRequired) 0x01 else 0x00)
            write(e.appName.length); write(e.appName.toByteArray(Charsets.US_ASCII))
            write(e.accountName.length); write(e.accountName.toByteArray(Charsets.US_ASCII))
            write(seed.size); write(seed)
        }.toByteArray()
    }

    /** Delete = write payload with config zeroed and an empty seed (§6.4). */
    fun serializeDeleteEntry(appName: String, accountName: String): ByteArray =
        ByteArrayOutputStream().apply {
            write(0x00); write(0x00)               // type, algorithm
            write(0x00); write(0x00)               // timestep u16
            write(0x00); write(0x00)               // code_length, btn
            write(appName.length); write(appName.toByteArray(Charsets.US_ASCII))
            write(accountName.length); write(accountName.toByteArray(Charsets.US_ASCII))
            write(0x00)                            // seed_len = 0
        }.toByteArray()

    /** ENUM_CODES READ_ALL request: 0x03 || u64_be(timestamp) (§6.1). */
    fun serializeReadAll(timestampSeconds: Long): ByteArray =
        byteArrayOf(0x03) + u64be(timestampSeconds)

    /** ENUM_CODES READ_ONE request (§6.2). */
    fun serializeReadOne(timestampSeconds: Long, app: String, acct: String): ByteArray =
        ByteArrayOutputStream().apply {
            write(0x01); write(u64be(timestampSeconds))
            write(app.length); write(app.toByteArray(Charsets.US_ASCII))
            write(acct.length); write(acct.toByteArray(Charsets.US_ASCII))
        }.toByteArray()

    fun serializeContinue(timestampSeconds: Long): ByteArray = u64be(timestampSeconds)

    private fun u64be(v: Long): ByteArray {
        val b = ByteArray(8); var x = v
        for (i in 7 downTo 0) { b[i] = (x and 0xFF).toByte(); x = x ushr 8 }
        return b
    }

    /** Client-side validation from §9; throws IllegalArgumentException on violation. */
    fun validateWrite(e: Entry, seed: ByteArray) {
        require(e.timestep in 1..0xFFFF) { "timestep must be 1..65535" }
        require(e.codeLength in 4..10) { "code_length must be 4..10" }
        require(e.appName.toByteArray(Charsets.US_ASCII).size in 0..64) { "app_name 0..64 bytes" }
        require(e.accountName.toByteArray(Charsets.US_ASCII).size in 1..64) { "account_name 1..64 bytes" }
        require(seed.size in 1..64) { "decoded seed must be 1..64 bytes" }
    }
}
