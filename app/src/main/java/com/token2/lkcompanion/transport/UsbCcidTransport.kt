package com.token2.lkcompanion.transport

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import java.io.ByteArrayOutputStream

/**
 * USB transport speaking CCID (USB Chip/Smart Card Interface Devices, class
 * 0x0B) over the Android USB Host API. We implement the minimal CCID bulk
 * message subset needed to exchange APDUs:
 *   - PC_to_RDR_IccPowerOn  (0x62) -> RDR_to_PC_DataBlock (ATR)
 *   - PC_to_RDR_XfrBlock    (0x6F) -> RDR_to_PC_DataBlock (response)
 *
 * This is the part with no Android platform helper — unlike NFC, we assemble
 * the 10-byte CCID header and bulk-transfer it ourselves. Time-extension
 * responses (RDR_to_PC with status "time extension requested") are retried.
 *
 * NOTE: verified for structure against the CCID 1.1 spec; must be exercised
 * against real reader hardware before relying on it. Sequence-number handling
 * and multi-block XfrBlock chaining for >maxPacket payloads are implemented
 * conservatively and are the most likely spot to need hardware tuning.
 */
class UsbCcidTransport(
    private val connection: UsbDeviceConnection,
    private val ccidInterface: UsbInterface,
    private val bulkIn: UsbEndpoint,
    private val bulkOut: UsbEndpoint,
) : SmartCardTransport {

    override val displayName: String = "USB security key (USB CCID)"
    override var isConnected: Boolean = false
        private set

    private var sequence: Int = 0

    /** From the ATR the card answered power-on with ([Atr.historicalBytes]). */
    override var historicalBytes: ByteArray? = null
        private set

    init {
        connection.claimInterface(ccidInterface, true)
        historicalBytes = Atr.historicalBytes(powerOn())
        isConnected = true
    }

    private fun nextSeq(): Int { val s = sequence; sequence = (sequence + 1) and 0xFF; return s }

    /** Build a CCID bulk-OUT message: 10-byte header + payload. */
    private fun ccidMessage(messageType: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(messageType and 0xFF)
        val len = payload.size
        out.write(len and 0xFF)
        out.write((len ushr 8) and 0xFF)
        out.write((len ushr 16) and 0xFF)
        out.write((len ushr 24) and 0xFF)
        out.write(0x00)            // bSlot
        out.write(nextSeq())       // bSeq
        out.write(0x00)            // msg-specific byte 0
        out.write(0x00)            // msg-specific byte 1
        out.write(0x00)            // msg-specific byte 2
        out.write(payload)
        return out.toByteArray()
    }

    private fun bulkSend(message: ByteArray) {
        var off = 0
        val max = bulkOut.maxPacketSize
        while (off < message.size) {
            val n = minOf(max, message.size - off)
            val sent = connection.bulkTransfer(
                bulkOut, message.copyOfRange(off, off + n), n, TIMEOUT_MS)
            if (sent < 0) throw TransportException("CCID bulk OUT failed at offset $off")
            off += sent
        }
    }

    /** Read one full CCID RDR_to_PC message, looping over time-extension status. */
    private fun bulkReceive(): ByteArray {
        while (true) {
            val buf = ByteArray(bulkIn.maxPacketSize.coerceAtLeast(64))
            val acc = ByteArrayOutputStream()
            var read = connection.bulkTransfer(bulkIn, buf, buf.size, TIMEOUT_MS)
            if (read < 0) throw TransportException("CCID bulk IN failed")
            acc.write(buf, 0, read)
            // header carries dwLength of the payload; pull more packets if short
            val header = acc.toByteArray()
            if (header.size < 10) continue
            val payloadLen = (header[1].toInt() and 0xFF) or
                ((header[2].toInt() and 0xFF) shl 8) or
                ((header[3].toInt() and 0xFF) shl 16) or
                ((header[4].toInt() and 0xFF) shl 24)
            while (acc.size() < 10 + payloadLen) {
                read = connection.bulkTransfer(bulkIn, buf, buf.size, TIMEOUT_MS)
                if (read < 0) throw TransportException("CCID bulk IN (cont) failed")
                acc.write(buf, 0, read)
            }
            val msg = acc.toByteArray()
            val status = msg[7].toInt() and 0xFF
            val iccStatus = status and 0x03
            val cmdStatus = (status ushr 6) and 0x03
            // cmdStatus 2 == time extension requested -> wait and read again
            if (cmdStatus == 2) continue
            if (cmdStatus == 1) {
                val error = msg.getOrElse(8) { 0 }.toInt() and 0xFF
                throw TransportException("CCID command failed, error=0x%02X icc=0x%02X"
                    .format(error, iccStatus))
            }
            return msg.copyOfRange(10, 10 + payloadLen)
        }
    }

    private fun powerOn(): ByteArray {
        bulkSend(ccidMessage(0x62, ByteArray(0)))   // PC_to_RDR_IccPowerOn
        return bulkReceive()                         // ATR
    }

    override fun selectApplet(aid: ByteArray): ByteArray {
        // No Le on SELECT — see NfcTransport for why.
        val resp = transceive(Apdu.build(0x00, 0xA4, 0x04, 0x00, aid))
        if (!resp.isSuccess)
            throw appletSelectionException(aid, resp.sw)
        return resp.data
    }

    override fun transceive(command: ByteArray): ResponseApdu {
        val send: (ByteArray) -> ByteArray = { apdu ->
            bulkSend(ccidMessage(0x6F, apdu))       // PC_to_RDR_XfrBlock
            bulkReceive()
        }
        val first = Apdu.parseResponse(send(command))
        return Apdu.drainChaining(first, send)
    }

    override fun close() {
        try {
            connection.releaseInterface(ccidInterface)
            connection.close()
        } catch (_: Exception) { } finally { isConnected = false }
    }

    companion object {
        private const val TIMEOUT_MS = 5_000
        const val USB_CLASS_CCID = 0x0B

        /** Pick the CCID interface + its bulk endpoints, or null if not a CCID device. */
        fun findCcidEndpoints(iface: UsbInterface): Pair<UsbEndpoint, UsbEndpoint>? {
            if (iface.interfaceClass != USB_CLASS_CCID) return null
            var bin: UsbEndpoint? = null; var bout: UsbEndpoint? = null
            for (i in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(i)
                if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                    if (ep.direction == UsbConstants.USB_DIR_IN) bin = ep else bout = ep
                }
            }
            return if (bin != null && bout != null) bin to bout else null
        }
    }
}
