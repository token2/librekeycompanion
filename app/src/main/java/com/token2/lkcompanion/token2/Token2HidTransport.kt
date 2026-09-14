package com.token2.lkcompanion.token2

import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbInterface
import com.token2.lkcompanion.transport.TransportException
import java.io.ByteArrayOutputStream

/**
 * USB-HID transport for Token2 OTP-on-FIDO (§4). Unlike CCID, HID doesn't carry
 * APDUs natively, so each APDU is chunked across 64-byte feature reports with the
 * `00 21` magic, a sequence/flags byte, and a per-chunk length (≤61). The `0xC0`
 * flag means "still working, poll again" — used while the device waits for a
 * button press; we must NOT advance the message counter on those.
 *
 * STATUS: framing follows the spec §4 precisely (verified by construction against
 * the worked layout), but HID feature-report I/O on Android varies by device and
 * this path is not hardware-exercised here. The button-wait polling and the
 * report-ID handling (some stacks strip the leading 0x00) are the likely tuning
 * points. Validate against a physical Token2 key before relying on it.
 *
 * Token2 OTP HID interface: vendor 0x349E, product 0x0022.
 */
class Token2HidTransport(
    private val connection: UsbDeviceConnection,
    private val hidInterface: UsbInterface,
) {
    companion object {
        const val VENDOR_ID = 0x349E
        const val PRODUCT_ID = 0x0022
        private const val MAGIC0 = 0x00
        private const val MAGIC1 = 0x21
        private const val MAX_CHUNK = 61
        private const val FLAG_MORE = 0x20
        private const val FLAG_POLL = 0xC0
        private const val REPORT_LEN = 64        // payload (report ID handled separately)
        private const val MAX_POLLS = 50
    }

    var onButtonWait: (() -> Unit)? = null

    init { connection.claimInterface(hidInterface, true) }

    /**
     * Send one APDU and return the response data with the trailing SW stripped,
     * raising on a non-9000 status word.
     */
    fun sendCommand(apdu: ByteArray, detectButtonWait: Boolean = false): ByteArray {
        sendChunks(apdu)
        val full = receive(detectButtonWait)
        return checkStatus(full)
    }

    private fun sendChunks(apdu: ByteArray) {
        val chunks = apdu.toList().chunked(MAX_CHUNK)
        chunks.forEachIndexed { i, chunk ->
            val last = i == chunks.lastIndex
            val flags = if (last) 0x00 else FLAG_MORE
            val byte2 = flags or (i % 16)
            val report = ByteArray(REPORT_LEN)
            report[0] = MAGIC1.toByte()                 // offset 1 of the 65; here index 0 of payload
            // NOTE: many Android HID paths expect the report-ID byte separate from payload.
            // We model the 64-byte payload here: [21][byte2][len][chunk...]
            report[1] = byte2.toByte()
            report[2] = chunk.size.toByte()
            for (j in chunk.indices) report[3 + j] = chunk[j]
            writeReport(report)
        }
    }

    private fun receive(detectButtonWait: Boolean): ByteArray {
        val acc = ByteArrayOutputStream()
        var received = 0
        var polls = 0
        while (true) {
            val payload = readReport()
            // Some stacks drop the leading report-ID; check magic at 0..1.
            if ((payload[0].toInt() and 0xFF) != MAGIC1 &&
                !(payload.size >= 2 && (payload[0].toInt() and 0xFF) == MAGIC0 &&
                  (payload[1].toInt() and 0xFF) == MAGIC1)) {
                // tolerate either alignment; locate the 0x21 magic
            }
            val base = if ((payload[0].toInt() and 0xFF) == MAGIC1) 0 else 1
            val flagsByte = payload[base + 1].toInt() and 0xFF
            val flags = flagsByte and 0xF0
            val seq = flagsByte and 0x0F

            if (flags == FLAG_POLL) {
                polls++
                if (detectButtonWait && polls == 3) onButtonWait?.invoke()
                if (polls > MAX_POLLS) throw TransportException("HID poll timeout")
                continue                                // don't advance counter or append
            }
            if (seq != received % 16) throw TransportException("HID sequence mismatch")
            received++
            val len = payload[base + 2].toInt() and 0xFF
            acc.write(payload, base + 3, len)
            if (flags and FLAG_MORE == 0) break
        }
        return acc.toByteArray()
    }

    private fun checkStatus(full: ByteArray): ByteArray {
        if (full.size < 2) throw TransportException("HID response too short")
        val sw = ((full[full.size - 2].toInt() and 0xFF) shl 8) or (full[full.size - 1].toInt() and 0xFF)
        val data = full.copyOfRange(0, full.size - 2)
        when (sw) {
            0x9000 -> return data
            0x6A80, 0x6A83 -> throw Token2Exception.EntryNotFound
            0x6A84 -> throw Token2Exception.NotEnoughSpace
            0x6A86 -> throw Token2Exception.HidNotSupported
            0x6FF9 -> throw Token2Exception.ButtonPressRequired
            else -> throw Token2Exception.BadStatus(sw)
        }
    }

    // --- raw HID feature report I/O via UsbRequest on the interface's endpoints ---
    private fun writeReport(payload64: ByteArray) {
        // Prepend report ID 0x00 -> 65 bytes total.
        val out = ByteArray(65)
        System.arraycopy(payload64, 0, out, 1, 64)
        val ep = (0 until hidInterface.endpointCount)
            .map { hidInterface.getEndpoint(it) }
            .firstOrNull { it.direction == android.hardware.usb.UsbConstants.USB_DIR_OUT }
            ?: throw TransportException("no HID OUT endpoint")
        val n = connection.bulkTransfer(ep, out, out.size, 3000)
        if (n < 0) throw TransportException("HID write failed")
    }

    private fun readReport(): ByteArray {
        val ep = (0 until hidInterface.endpointCount)
            .map { hidInterface.getEndpoint(it) }
            .firstOrNull { it.direction == android.hardware.usb.UsbConstants.USB_DIR_IN }
            ?: throw TransportException("no HID IN endpoint")
        val buf = ByteArray(65)
        val n = connection.bulkTransfer(ep, buf, buf.size, 3000)
        if (n < 0) throw TransportException("HID read failed")
        // strip the report-ID byte if present (n==65), else return as-is
        return if (n == 65) buf.copyOfRange(1, 65) else buf.copyOfRange(0, n)
    }

    fun close() {
        runCatching { connection.releaseInterface(hidInterface); connection.close() }
    }
}

/** Token2-specific protocol exceptions (§3.1 / §8.4). */
sealed class Token2Exception(message: String) : Exception(message) {
    object EntryNotFound : Token2Exception("entry not found")
    object NotEnoughSpace : Token2Exception("not enough space on device")
    object HidNotSupported : Token2Exception("HOTP-over-HID not supported on this model")
    object ButtonPressRequired : Token2Exception("timed out waiting for button press")
    // --- OTP PIN (privacy protection) ---
    object PinNotVerified : Token2Exception("OTP PIN not verified or incorrect")
    object PinBlocked : Token2Exception("OTP PIN is locked out; erase-all is the only recovery")
    object PinWrongState : Token2Exception("command not allowed in the current PIN state")
    class PinUnsupported(val sw: Int, val ctx: String = "") :
        Token2Exception(
            "OTP PIN command failed (SW=%04X%s)".format(sw, if (ctx.isNotEmpty()) " at $ctx" else "")
        )
    object PinTransportUnavailable :
        Token2Exception("OTP PIN commands require the CCID/NFC transport")
    /** §1.20: fingerprint-protected OTP — the on-key fingerprint check did not pass. */
    class FingerprintNotVerified(val sw: Int) :
        Token2Exception("fingerprint verification failed or timed out (SW=%04X)".format(sw))
    /** §1.20: enabling FP protection was refused because no fingerprint is enrolled (0x6984). */
    object NoFingerprintEnrolled :
        Token2Exception("no fingerprint is enrolled on this key — enroll one via the key's FIDO2 fingerprint setup first")
    class BadStatus(val sw: Int) : Token2Exception("unexpected status %04X".format(sw))
}
