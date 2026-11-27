package com.token2.lkcompanion.piv

import java.security.MessageDigest

/**
 * Minimal DER / X.509 parser, just enough to surface read-only display fields from
 * a PIV slot certificate: subject and issuer common names, validity dates, serial,
 * public-key algorithm and size, and a SHA-256 fingerprint of the DER.
 *
 * This is NOT a validating parser and performs no signature checking — it walks the
 * DER structure to pull human-readable metadata for the UI. Verified against real
 * certificates (see verification harness).
 *
 * Certificate ::= SEQUENCE {
 *   tbsCertificate    SEQUENCE {
 *     [0] version, serialNumber INTEGER, signature AlgId, issuer Name,
 *     validity SEQUENCE { notBefore Time, notAfter Time },
 *     subject Name, subjectPublicKeyInfo SEQUENCE { algorithm AlgId, key BIT STRING } },
 *   signatureAlgorithm AlgId, signatureValue BIT STRING }
 */
object X509 {

    data class CertInfo(
        val subjectCn: String?,
        val issuerCn: String?,
        val notBefore: String?,
        val notAfter: String?,
        val serialHex: String?,
        val keyAlgorithm: String?,   // e.g. "RSA 2048", "ECC P-256"
        val sha256Fingerprint: String,
    )

    // ---- DER primitives ----

    private class Reader(val b: ByteArray, var pos: Int = 0, val end: Int = b.size) {
        fun peekTag(): Int = b[pos].toInt() and 0xFF

        /** Read a TLV; return (tag, contentStart, contentEnd) and advance past it. */
        fun readTlv(): Triple<Int, Int, Int> {
            val tag = b[pos].toInt() and 0xFF; pos++
            var len = b[pos].toInt() and 0xFF; pos++
            if (len and 0x80 != 0) {
                val n = len and 0x7F
                len = 0
                repeat(n) { len = (len shl 8) or (b[pos].toInt() and 0xFF); pos++ }
            }
            val start = pos
            val finish = pos + len
            pos = finish
            return Triple(tag, start, finish)
        }
    }

    /** Enter a constructed TLV, returning a Reader scoped to its contents. */
    private fun Reader.enter(): Reader {
        val (_, s, e) = readTlv()
        return Reader(b, s, e)
    }

    fun parse(der: ByteArray): CertInfo {
        val fp = MessageDigest.getInstance("SHA-256").digest(der)
            .joinToString(":") { "%02X".format(it) }

        var subjectCn: String? = null
        var issuerCn: String? = null
        var notBefore: String? = null
        var notAfter: String? = null
        var serialHex: String? = null
        var keyAlg: String? = null

        try {
            val top = Reader(der)
            val cert = top.enter()          // into Certificate SEQUENCE
            val tbs = cert.enter()          // into tbsCertificate SEQUENCE

            // optional [0] version
            if (tbs.peekTag() == 0xA0) tbs.readTlv()

            // serialNumber INTEGER
            run {
                val (_, s, e) = tbs.readTlv()
                serialHex = der.copyOfRange(s, e).joinToString("") { "%02X".format(it) }
                    .trimStart('0').ifEmpty { "0" }
            }

            tbs.readTlv()                   // signature AlgorithmIdentifier (skip)

            issuerCn = readNameCn(tbs, der)        // issuer Name

            // validity SEQUENCE { notBefore, notAfter }
            run {
                val v = tbs.enter()
                notBefore = readTime(v, der)
                notAfter = readTime(v, der)
            }

            subjectCn = readNameCn(tbs, der)       // subject Name

            keyAlg = readPublicKeyInfo(tbs, der)   // subjectPublicKeyInfo
        } catch (_: Exception) {
            // Best-effort: whatever we parsed before a malformed field still shows.
        }

        return CertInfo(subjectCn, issuerCn, notBefore, notAfter, serialHex, keyAlg, fp)
    }

    /** Name ::= SEQUENCE OF RDN; pull the CN (OID 2.5.4.3) attribute value. */
    private fun readNameCn(parent: Reader, der: ByteArray): String? {
        val name = parent.enter()           // into Name SEQUENCE
        val cnOid = byteArrayOf(0x55, 0x04, 0x03)   // 2.5.4.3
        var cn: String? = null
        while (name.pos < name.end) {
            val rdn = name.enter()          // SET OF AttributeTypeAndValue
            while (rdn.pos < rdn.end) {
                val atv = rdn.enter()       // SEQUENCE { type OID, value }
                val (_, os, oe) = atv.readTlv()   // OID
                val oid = der.copyOfRange(os, oe)
                val (vt, vs, ve) = atv.readTlv()  // value (UTF8String/PrintableString/etc.)
                if (oid.contentEquals(cnOid)) {
                    cn = String(der.copyOfRange(vs, ve), Charsets.UTF_8)
                }
            }
        }
        return cn
    }

    /** Time is UTCTime (0x17) or GeneralizedTime (0x18); return as a readable date. */
    private fun readTime(parent: Reader, der: ByteArray): String? {
        val (tag, s, e) = parent.readTlv()
        val raw = String(der.copyOfRange(s, e), Charsets.US_ASCII)
        // UTCTime: YYMMDDHHMMSSZ ; GeneralizedTime: YYYYMMDDHHMMSSZ
        return try {
            val (yyyy, rest) = if (tag == 0x17) {
                val yy = raw.substring(0, 2).toInt()
                val year = if (yy >= 50) 1900 + yy else 2000 + yy
                year.toString() to raw.substring(2)
            } else {
                raw.substring(0, 4) to raw.substring(4)
            }
            val mm = rest.substring(0, 2); val dd = rest.substring(2, 4)
            "$yyyy-$mm-$dd"
        } catch (_: Exception) { raw }
    }

    /** subjectPublicKeyInfo: algorithm OID + key; derive a friendly "RSA 2048" / "ECC P-256". */
    private fun readPublicKeyInfo(parent: Reader, der: ByteArray): String? {
        val spki = parent.enter()           // SEQUENCE
        val alg = spki.enter()              // AlgorithmIdentifier SEQUENCE
        val (_, os, oe) = alg.readTlv()     // algorithm OID
        val oid = der.copyOfRange(os, oe)

        val rsaOid = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)
        val ecOid = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)
        // RFC 8410: the algorithm OID alone names the key, with no parameters.
        val ed25519Oid = byteArrayOf(0x2B, 0x65, 0x70)   // 1.3.101.112
        val x25519Oid = byteArrayOf(0x2B, 0x65, 0x6E)    // 1.3.101.110

        return when {
            oid.contentEquals(ed25519Oid) -> "Ed25519"
            oid.contentEquals(x25519Oid) -> "X25519"
            oid.contentEquals(rsaOid) -> {
                // params skipped; key is a BIT STRING wrapping an RSA SEQUENCE { modulus, exp }
                val (_, ks, _) = spki.readTlv()      // BIT STRING
                // first content byte of BIT STRING is the unused-bits count
                val inner = Reader(der, ks + 1, der.size)
                val rsa = inner.enter()              // RSAPublicKey SEQUENCE
                val (_, ms, me) = rsa.readTlv()      // modulus INTEGER
                var bits = (me - ms) * 8
                // strip the leading 0x00 sign byte if present
                if (der[ms].toInt() == 0x00) bits -= 8
                "RSA $bits"
            }
            oid.contentEquals(ecOid) -> {
                // curve OID is the AlgorithmIdentifier parameter
                val (_, cs, ce) = alg.readTlv()      // curve OID
                "ECC " + curveName(der.copyOfRange(cs, ce))
            }
            else -> "Unknown"
        }
    }

    private fun curveName(oid: ByteArray): String {
        val p256 = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)
        val p384 = byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x22)
        val p521 = byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x23)
        val secp256k1 = byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x0A)   // 1.3.132.0.10
        return when {
            oid.contentEquals(p256) -> "P-256"
            oid.contentEquals(p384) -> "P-384"
            oid.contentEquals(p521) -> "P-521"
            oid.contentEquals(secp256k1) -> "secp256k1"
            else -> "(curve?)"
        }
    }
}
