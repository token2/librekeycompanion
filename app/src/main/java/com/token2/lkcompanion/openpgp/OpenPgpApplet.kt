package com.token2.lkcompanion.openpgp

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * OpenPGP Card v3.4 applet client (a read-only subset of the OpenPGP card byte
 * layer over the Android transport).
 *
 * ── SCOPE ──────────────────────────────────────────────────────────────────
 * IMPLEMENTED & low-risk: SELECT, and the READ path — GET DATA for Application
 * Related Data (0x006E) and Cardholder Related Data (0x0065), parsed as BER-TLV.
 * These are non-destructive and safe to exercise.
 *
 * NOT implemented (intentionally — these are security-critical and must be
 * built against the spec + a real card): key generation/import (GENERATE
 * ASYMMETRIC KEY PAIR / PUT DATA), PSO:CDS signing, PSO:DEC decryption, PIN
 * (PW1/PW3) verification, and factory RESET. these are intentionally out of scope in
 * Rust; porting them is a deliberate follow-up, not something to fake here.
 */
class OpenPgpApplet(private val transport: SmartCardTransport) {

    companion object {
        val AID = byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x01, 0x24, 0x01)
        private const val INS_GET_DATA = 0xCA
        private const val DO_APPLICATION_RELATED = 0x006E
        private const val DO_CARDHOLDER_RELATED = 0x0065
        private const val DO_URL = 0x5F50
    }

    /** One of the three OpenPGP key slots. */
    data class KeySlot(
        val name: String,            // "Signature", "Decryption", "Authentication"
        val present: Boolean,        // fingerprint is non-zero
        val fingerprint: String?,    // hex, or null if empty
        val algorithm: String?,      // e.g. "RSA 2048", "Ed25519", "NIST P-256"
        val generated: String?,      // creation date (yyyy-MM-dd) or null
    )

    data class CardStatus(
        val aidHex: String,
        val specVersion: String,
        val cardholderName: String?,
        val url: String?,
        val signatureKeyFingerprint: String?,
        val keys: List<KeySlot> = emptyList(),
        val pin1Retries: Int? = null,
        val pin3Retries: Int? = null,
        val serialHex: String? = null,
    )

    fun select(): ByteArray = transport.selectApplet(AID)

    /** Read application + cardholder data and surface a non-sensitive summary. */
    fun status(): CardStatus {
        select()
        // Each GET DATA is independent; a failure on one optional object must not
        // sink the whole status read. Only SELECT failing means "no applet".
        val appData = runCatching { getData(DO_APPLICATION_RELATED) }.getOrNull()
        val cardholder = runCatching { getData(DO_CARDHOLDER_RELATED) }.getOrNull()
        val urlBytes = runCatching { getData(DO_URL) }.getOrNull()

        val tree = appData?.let { BerTlv.parse(it) }
        val fingerprints = tree?.find(0x00C5)          // 60 bytes: 3 × 20
        val timestamps = tree?.find(0x00CD)            // 12 bytes: 3 × 4 (epoch seconds)
        val pwStatus = tree?.find(0x00C4)              // PW status incl. retry counters
        val aid = tree?.find(0x004F)                   // full AID (incl. card serial)

        val sigFp = fingerprints?.takeIf { it.size >= 20 }?.copyOfRange(0, 20)
            ?.joinToString("") { "%02X".format(it) }

        val slotNames = listOf("Signature", "Decryption", "Authentication")
        val algoTags = listOf(0x00C1, 0x00C2, 0x00C3)
        val keys = ArrayList<KeySlot>()
        for (idx in 0 until 3) {
            val fp = fingerprints?.takeIf { it.size >= (idx + 1) * 20 }
                ?.copyOfRange(idx * 20, idx * 20 + 20)
            val present = fp != null && fp.any { it.toInt() != 0 }
            val ts = timestamps?.takeIf { it.size >= (idx + 1) * 4 }
                ?.copyOfRange(idx * 4, idx * 4 + 4)
            keys.add(KeySlot(
                name = slotNames[idx],
                present = present,
                fingerprint = if (present) fp!!.joinToString("") { "%02X".format(it) } else null,
                algorithm = tree?.find(algoTags[idx])?.let { algorithmName(it) },
                generated = ts?.let { epochToDate(it) }?.takeIf { present },
            ))
        }

        // PW status bytes: [0]=PW1 valid-multiple, [1]=max PW1 len, [2]=max RC len,
        // [3]=max PW3 len, [4]=PW1 tries left, [5]=RC tries left, [6]=PW3 tries left.
        val pin1 = pwStatus?.takeIf { it.size >= 7 }?.get(4)?.toInt()?.and(0xFF)
        val pin3 = pwStatus?.takeIf { it.size >= 7 }?.get(6)?.toInt()?.and(0xFF)
        // Card serial = last 4 bytes of the manufacturer/serial portion of the AID.
        val serial = aid?.takeIf { it.size >= 14 }?.copyOfRange(10, 14)
            ?.joinToString("") { "%02X".format(it) }

        val name = cardholder?.let { BerTlv.parse(it).find(0x005B)?.toString(Charsets.UTF_8) }

        return CardStatus(
            aidHex = AID.joinToString("") { "%02X".format(it) },
            specVersion = "3.4 (declared)",
            cardholderName = name,
            url = urlBytes?.toString(Charsets.UTF_8),
            signatureKeyFingerprint = sigFp,
            keys = keys,
            pin1Retries = pin1,
            pin3Retries = pin3,
            serialHex = serial,
        )
    }

    /** OpenPGP algorithm attributes: first byte is the algorithm id. */
    private fun algorithmName(attr: ByteArray): String {
        if (attr.isEmpty()) return "?"
        return when (attr[0].toInt() and 0xFF) {
            0x01 -> {  // RSA: bytes 1..2 = modulus bit length (big-endian)
                if (attr.size >= 3) {
                    val bits = ((attr[1].toInt() and 0xFF) shl 8) or (attr[2].toInt() and 0xFF)
                    "RSA $bits"
                } else "RSA"
            }
            0x12 -> "ECDH " + curveFromOid(attr)      // ECDH
            0x13 -> "ECDSA " + curveFromOid(attr)     // ECDSA
            0x16 -> "EdDSA " + curveFromOid(attr)     // EdDSA (Ed25519)
            else -> "alg 0x%02X".format(attr[0].toInt() and 0xFF)
        }
    }

    /** Map the OID bytes (after the algo id) to a friendly curve name. */
    private fun curveFromOid(attr: ByteArray): String {
        if (attr.size < 2) return ""
        val oid = attr.copyOfRange(1, attr.size)
        fun eq(vararg b: Int) = oid.size >= b.size &&
            b.indices.all { (oid[it].toInt() and 0xFF) == b[it] }
        return when {
            eq(0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01) -> "Ed25519"
            eq(0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01) -> "Curve25519"
            eq(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07) -> "P-256"
            eq(0x2B, 0x81, 0x04, 0x00, 0x22) -> "P-384"
            eq(0x2B, 0x81, 0x04, 0x00, 0x23) -> "P-521"
            eq(0x2B, 0x81, 0x04, 0x00, 0x0A) -> "secp256k1"
            else -> "(curve?)"
        }
    }

    private fun epochToDate(b: ByteArray): String? {
        if (b.size < 4) return null
        val secs = ((b[0].toInt() and 0xFF).toLong() shl 24) or
                   ((b[1].toInt() and 0xFF).toLong() shl 16) or
                   ((b[2].toInt() and 0xFF).toLong() shl 8) or
                   (b[3].toInt() and 0xFF).toLong()
        if (secs == 0L) return null
        return java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(java.util.Date(secs * 1000))
    }

    private fun getData(tag: Int): ByteArray {
        val resp = transport.transceive(
            Apdu.build(0x00, INS_GET_DATA, (tag ushr 8) and 0xFF, tag and 0xFF, le = 0x00))
        if (!resp.isSuccess) throw TransportException("GET DATA SW=${"%04X".format(resp.sw)}")
        return resp.data
    }

    fun sign(): Nothing =
        throw NotImplementedError("PSO:CDS signing not implemented in read-only build.")
    fun decrypt(): Nothing =
        throw NotImplementedError("PSO:DEC not implemented in read-only build.")
    fun generateKey(): Nothing =
        throw NotImplementedError("Key generation not implemented in read-only build.")
}

/** Minimal BER-TLV reader supporting 1- and 2-byte tags and short/long length. */
object BerTlv {
    data class Node(val tag: Int, val value: ByteArray, val children: List<Node>)

    fun parse(data: ByteArray): TlvTree = TlvTree(parseNodes(data, 0, data.size))

    private fun parseNodes(data: ByteArray, start: Int, end: Int): List<Node> {
        val nodes = ArrayList<Node>()
        var i = start
        while (i < end) {
            // Skip filler/padding zero bytes between TLVs (some cards emit 0x00).
            if (data[i].toInt() == 0x00) { i++; continue }

            var tag = data[i].toInt() and 0xFF; i++
            if (tag and 0x1F == 0x1F) {                 // multi-byte tag
                if (i >= end) break                     // truncated tag
                tag = (tag shl 8) or (data[i].toInt() and 0xFF); i++
                // consume further tag bytes while high bit set
                while (i < end && (tag and 0x80) != 0 && (data[i].toInt() and 0x80) != 0) {
                    tag = (tag shl 8) or (data[i].toInt() and 0xFF); i++
                }
            }
            if (i >= end) break                         // no length byte
            var len = data[i].toInt() and 0xFF; i++
            if (len and 0x80 != 0) {                    // long form
                val n = len and 0x7F
                if (n == 0 || i + n > end) break        // indefinite/invalid length
                len = 0
                repeat(n) { len = (len shl 8) or (data[i].toInt() and 0xFF); i++ }
            }
            if (len < 0 || i + len > end) break          // value overruns buffer
            val value = data.copyOfRange(i, i + len)
            val constructed = (tag and 0x20) != 0 ||
                (tag > 0xFF && ((tag ushr 8) and 0x20) != 0)
            val children = if (constructed && value.isNotEmpty())
                parseNodes(value, 0, value.size) else emptyList()
            nodes.add(Node(tag, value, children))
            i += len
        }
        return nodes
    }
}

class TlvTree(private val roots: List<BerTlv.Node>) {
    fun find(tag: Int): ByteArray? = search(roots, tag)
    private fun search(nodes: List<BerTlv.Node>, tag: Int): ByteArray? {
        for (n in nodes) {
            if (n.tag == tag) return n.value
            search(n.children, tag)?.let { return it }
        }
        return null
    }
}
