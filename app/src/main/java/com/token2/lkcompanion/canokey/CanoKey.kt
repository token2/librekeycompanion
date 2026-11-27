package com.token2.lkcompanion.canokey

import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * CanoKey (canokeys.org) identification through its Admin applet, which
 * reports the firmware version, the hardware variant and the serial number
 * without a PIN. Commands and rules from canokey-core 3.1.2 (`applets/admin`,
 * `src/apdu.c`); the same since release 1.6.2.
 *
 * A CanoKey names itself in the historical bytes of the ATR its USB CCID
 * interface answers (`Canokey`). Held to a phone, its ATS has no historical
 * bytes, so only a card with none is asked: the Admin applet's SELECT goes
 * to no card that names itself otherwise.
 *
 * Selecting the Admin applet ends any other applet's session on the key
 * (an unlocked OATH password, a verified PIN): ask before selecting the
 * applet the work is for.
 */
object CanoKey {

    /** The Admin applet's AID. */
    val ADMIN_AID = byteArrayOf(0xF0.toByte(), 0x00, 0x00, 0x00, 0x00)

    /** The historical bytes of a CanoKey's USB CCID ATR. */
    private val CCID_HISTORICAL_BYTES = "Canokey".toByteArray(Charsets.US_ASCII)

    private val READ_FIRMWARE_VERSION = byteArrayOf(0x00, 0x31, 0x00, 0x00, 0x00)
    private val READ_HARDWARE_VARIANT = byteArrayOf(0x00, 0x31, 0x01, 0x00, 0x00)
    private val READ_SERIAL = byteArrayOf(0x00, 0x32, 0x00, 0x00, 0x00)

    data class Info(
        /** As the key gives it, e.g. `3.1.2`. */
        val firmware: String,
        /** The hardware variant text, e.g. `CanoKey Canary`, when it gives one. */
        val hardware: String?,
        /** The four-byte serial as CanoKey's own tools show it (decimal), when written. */
        val serial: Long?,
    )

    /** Whether the card on [transport] is a CanoKey. See the class doc for what is sent. */
    fun isCanoKey(transport: SmartCardTransport): Boolean = selectAdmin(transport) != null

    /** What the Admin applet reports, or null when the card is no CanoKey. */
    fun probe(transport: SmartCardTransport): Info? {
        val firmware = selectAdmin(transport) ?: return null
        return Info(
            firmware = firmware,
            hardware = read(transport, READ_HARDWARE_VARIANT)?.let(::parseText),
            serial = read(transport, READ_SERIAL)?.let(::parseSerial),
        )
    }

    /**
     * SELECT the Admin applet and read the firmware version, when the card may
     * be a CanoKey; the version, or null. A card that names itself otherwise,
     * or whose transport doesn't know, is sent nothing.
     */
    private fun selectAdmin(transport: SmartCardTransport): String? {
        val historical = transport.historicalBytes ?: return null
        if (historical.isNotEmpty() && !historical.contentEquals(CCID_HISTORICAL_BYTES)) return null
        try {
            transport.selectApplet(ADMIN_AID)
        } catch (_: TransportException) {
            return null
        }
        return read(transport, READ_FIRMWARE_VERSION)?.let(::parseFirmwareVersion)
    }

    private fun read(transport: SmartCardTransport, command: ByteArray): ByteArray? = try {
        transport.transceive(command).takeIf { it.isSuccess }?.data
    } catch (_: TransportException) {
        null
    }

    /**
     * A firmware version as the Admin applet writes it: an optional `v`, two
     * or three dot-separated numbers, then an optional `-` or `+` suffix.
     * Null for anything else, so that another card answering the same
     * command is not taken for a CanoKey.
     */
    fun parseFirmwareVersion(data: ByteArray): String? {
        val text = parseText(data) ?: return null
        return text.takeIf { VERSION.matches(it) }
    }

    private val VERSION = Regex("""v?\d{1,3}\.\d{1,3}(\.\d{1,3})?([-+]\S+)?""")

    /** UTF-8 text with surrounding whitespace and NUL padding trimmed; null when empty. */
    fun parseText(data: ByteArray): String? =
        String(data, Charsets.UTF_8).trim { it.isWhitespace() || it == '\u0000' }
            .takeIf { it.isNotEmpty() }

    /**
     * The serial from its four bytes, read big-endian, as CanoKey shows it.
     * Null for another length, and for all-zero or all-FF bytes, which every
     * key with no serial written reports alike.
     */
    fun parseSerial(data: ByteArray): Long? {
        if (data.size != 4) return null
        val serial = data.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        return serial.takeIf { it != 0L && it != 0xFFFF_FFFFL }
    }
}
