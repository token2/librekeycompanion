package com.token2.lkcompanion.transport

import android.nfc.tech.IsoDep

/**
 * NFC transport over ISO-DEP (ISO 14443-4). Wraps an [IsoDep] tag handle that
 * the foreground-dispatch / reader-mode callback hands us. Extended-length
 * APDUs are supported by the platform when [IsoDep.isExtendedLengthApduSupported]
 * is true; we fall back to short + chaining otherwise.
 *
 * Android already gives us a clean APDU pipe here (transceive), so unlike the
 * USB CCID path we don't assemble CCID block headers ourselves.
 */
class NfcTransport(private val isoDep: IsoDep) : SmartCardTransport {

    override val displayName: String = "NFC security key (NFC)"
    override val isConnected: Boolean get() = isoDep.isConnected

    /** The ATS historical bytes of an NFC-A tag; null for an NFC-B one. */
    override val historicalBytes: ByteArray? = isoDep.historicalBytes

    init {
        isoDep.timeout = 5_000
        if (!isoDep.isConnected) isoDep.connect()
    }

    override fun selectApplet(aid: ByteArray): ByteArray {
        // ISO SELECT by name. CRITICAL: no Le byte. A SELECT that appends Le=00
        // after the AID is rejected by many keys (SW 6700/6A86), which made every
        // applet's SELECT fail identically. The AID is the data; Le is omitted.
        val resp = transceive(Apdu.build(0x00, 0xA4, 0x04, 0x00, aid))
        if (!resp.isSuccess) {
            throw appletSelectionException(aid, resp.sw)
        }
        return resp.data
    }

    override fun transceive(command: ByteArray): ResponseApdu {
        try {
            val first = Apdu.parseResponse(isoDep.transceive(command))
            return Apdu.drainChaining(first) { isoDep.transceive(it) }
        } catch (e: Exception) {
            throw TransportException("NFC transceive failed", e)
        }
    }

    override fun close() {
        try { isoDep.close() } catch (_: Exception) { }
    }
}
