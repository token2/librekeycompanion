package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * Client for the YubiKey/Trussed OATH applet (the on-key TOTP/HOTP store), the
 * standard YKOATH byte layer — here over the
 * Android transport instead of PC/SC. Codes computed by LIST+CALCULATE are
 * produced by the key itself, not by [OathCore].
 *
 * Applet AID: A0 00 00 05 27 21 01
 *
 * Implemented: SELECT, LIST, CALCULATE, PUT, DELETE and VALIDATE (the password
 * unlock path). TLV tags follow the YKOATH protocol. SET CODE / RESET are
 * deliberately not implemented: they are destructive and untested on hardware.
 *
 * A password-protected applet still answers SELECT, so SELECT is not a usable
 * "is it locked" test on its own — it returns a challenge (tag 0x74) and every
 * later instruction fails with SW 6982 until [validate] succeeds. Instructions
 * here translate 6982 into [OathPasswordRequiredException] so callers can ask
 * for a password instead of surfacing a raw status word.
 *
 * STATUS: APDU structure follows the public YKOATH spec; CALCULATE/LIST/DELETE
 * are straightforward and well-covered by the spec, but this path has not been
 * exercised here against a physical key — validate before production use,
 * especially the challenge construction for TOTP CALCULATE (big-endian time /
 * period) and the SET PASSWORD key-derivation salt (the applet's device ID).
 */
class OathApplet(
    private val transport: SmartCardTransport,
    /**
     * The applet is a CanoKey's (canokey-core `applets/oath/oath.c`, the same
     * since 1.6.2). It speaks YKOATH with two differences that matter here: it
     * adds one to an HOTP counter *before* computing a code, so the counter it
     * stores is one below the first code's; and it refuses a PUT of a name it
     * already holds (6985) instead of overwriting it.
     */
    val isCanoKey: Boolean = false,
) {

    companion object {
        val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x21, 0x01)

        // Instructions
        private const val INS_PUT = 0x01
        private const val INS_DELETE = 0x02
        private const val INS_SET_CODE = 0x03
        private const val INS_RESET = 0x04
        private const val INS_LIST = 0xA1
        private const val INS_CALCULATE = 0xA2
        private const val INS_VALIDATE = 0xA3
        private const val INS_CALCULATE_ALL = 0xA4

        // TLV tags
        private const val TAG_NAME = 0x71
        private const val TAG_KEY = 0x73
        private const val TAG_CHALLENGE = 0x74
        private const val TAG_RESPONSE_FULL = 0x75
        private const val TAG_RESPONSE_TRUNC = 0x76
        private const val TAG_NO_RESPONSE = 0x77
        private const val TAG_PROPERTY = 0x78
        private const val TAG_VERSION = 0x79
        private const val TAG_IMF = 0x7A
        private const val TAG_ALGORITHM = 0x7B

        // Status words that mean "the applet is locked" / "wrong password".
        private const val SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
        private const val SW_INCORRECT_PARAMETERS = 0x6A80
        /** A CanoKey's answer to a PUT of a name it already holds. */
        private const val SW_CONDITIONS_NOT_SATISFIED = 0x6985

        // Type / algorithm nibbles packed into the KEY tag's first byte
        private const val TYPE_HOTP = 0x10
        private const val TYPE_TOTP = 0x20
        private const val ALG_SHA1 = 0x01
        private const val ALG_SHA256 = 0x02
        private const val ALG_SHA512 = 0x03

        // YKOATH implementations require credential keys to be at least 14 bytes.
        private const val MINIMUM_KEY_SIZE = 14
    }

    /**
     * @param challengeRequired a password is set; [validate] must run before any
     *   other instruction on this channel.
     * @param deviceId name TLV (0x71) — the PBKDF2 salt for the access key.
     * @param challenge the applet's challenge (0x74), empty when unprotected.
     * @param algorithm HMAC used by VALIDATE (0x7B), SHA-1 when the tag is absent.
     */
    data class AppletInfo(
        val version: String,
        val challengeRequired: Boolean,
        val deviceId: ByteArray = ByteArray(0),
        val challenge: ByteArray = ByteArray(0),
        val algorithm: Int = OathPassword.ALG_SHA1,
    )

    /** SELECT state for the currently open channel; cleared by a new SELECT. */
    private var selected: AppletInfo? = null
    private var validated = false

    /** Password set on the key and not yet unlocked on this channel. */
    val isLocked: Boolean
        get() = selected?.challengeRequired == true && !validated

    /** SELECT the OATH applet; returns version + whether a password is set. */
    fun select(): AppletInfo {
        val resp = transport.selectApplet(AID)
        val tlvs = parseTlvs(resp)
        val version = tlvs[TAG_VERSION]?.joinToString(".") { (it.toInt() and 0xFF).toString() }
            ?: "unknown"
        val challenge = tlvs[TAG_CHALLENGE] ?: ByteArray(0)
        val info = AppletInfo(
            version = version,
            challengeRequired = challenge.isNotEmpty(),
            deviceId = tlvs[TAG_NAME] ?: ByteArray(0),
            challenge = challenge,
            algorithm = tlvs[TAG_ALGORITHM]?.firstOrNull()?.toInt()?.and(0xFF)
                ?: OathPassword.ALG_SHA1,
        )
        selected = info
        validated = !info.challengeRequired
        return info
    }

    /**
     * VALIDATE (INS A3): prove knowledge of the access key, then check the
     * applet's own proof over a fresh challenge of ours. Must follow a [select]
     * on the same channel — the challenge is per-selection, and a failed attempt
     * requires re-selecting before retrying.
     *
     * Unlike a PIN, this consumes no retry counter: a wrong password is simply
     * rejected.
     *
     * @throws OathPasswordIncorrectException if the key rejects the access key.
     */
    fun validate(accessKey: ByteArray) {
        val info = selected
            ?: throw IllegalStateException("SELECT the OATH applet before VALIDATE")
        if (!info.challengeRequired) { validated = true; return }

        val ourChallenge = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_RESPONSE_FULL, OathPassword.hmac(info.algorithm, accessKey, info.challenge))
            writeTlv(TAG_CHALLENGE, ourChallenge)
        }.toByteArray()

        val resp = transport.transceive(
            Apdu.build(0x00, INS_VALIDATE, 0x00, 0x00, body, le = 0x00))
        when {
            resp.isSuccess -> Unit
            resp.sw == SW_SECURITY_STATUS_NOT_SATISFIED ||
                resp.sw == SW_INCORRECT_PARAMETERS ||
                (resp.sw and 0xFFF0) == 0x63C0 ->
                throw OathPasswordIncorrectException(info.deviceId)
            else -> throw TransportException("VALIDATE SW=${"%04X".format(resp.sw)}")
        }

        // Mutual authentication: the key must answer our challenge with the same
        // key, otherwise we are talking to something that only pretended to accept.
        val proof = parseTlvs(resp.data)[TAG_RESPONSE_FULL]
            ?: throw TransportException("VALIDATE response carried no proof")
        val expected = OathPassword.hmac(info.algorithm, accessKey, ourChallenge)
        if (!OathPassword.constantTimeEquals(expected, proof)) {
            throw TransportException("OATH applet failed mutual authentication")
        }
        validated = true
    }

    /** LIST credential names + their type/algo nibble. */
    fun list(): List<StoredCredential> {
        val resp = transport.transceive(Apdu.build(0x00, INS_LIST, 0x00, 0x00, le = 0x00))
        requireSuccess(resp, "LIST")
        val result = ArrayList<StoredCredential>()
        var i = 0
        val d = resp.data
        while (i < d.size) {
            val tag = d[i].toInt() and 0xFF; i++
            val len = d[i].toInt() and 0xFF; i++
            if (tag == 0x72) {
                val typeAlgo = d[i].toInt() and 0xFF
                val name = String(d, i + 1, len - 1, Charsets.UTF_8)
                result.add(StoredCredential(name, typeAlgo))
            }
            i += len
        }
        return result
    }

    /**
     * CALCULATE one code. For TOTP the challenge is the big-endian time-step
     * counter (unix / period); for HOTP the applet keeps its own counter and
     * the challenge is empty.
     */
    fun calculate(name: String, unixSeconds: Long, period: Int = 30,
                  truncate: Boolean = true): String {
        val challenge = ByteArray(8)
        val step = unixSeconds / period
        var c = step
        for (j in 7 downTo 0) { challenge[j] = (c and 0xFF).toByte(); c = c ushr 8 }

        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, name.toByteArray(Charsets.UTF_8))
            writeTlv(TAG_CHALLENGE, challenge)
        }.toByteArray()

        val p2 = if (truncate) 0x01 else 0x00
        val resp = transport.transceive(
            Apdu.build(0x00, INS_CALCULATE, 0x00, p2, body, le = 0x00))
        requireSuccess(resp, "CALCULATE")
        return decodeResponseCode(resp.data)
    }

    /** PUT a new credential onto the key. */
    fun put(cred: OathCredential) {
        val typeByte = when (cred.type) {
            OathCredential.Type.HOTP -> TYPE_HOTP
            OathCredential.Type.TOTP -> TYPE_TOTP
        } or when (cred.algo) {
            OathCore.HashAlgo.SHA1 -> ALG_SHA1
            OathCore.HashAlgo.SHA256 -> ALG_SHA256
            OathCore.HashAlgo.SHA512 -> ALG_SHA512
        }
        val secret = if (cred.secret.size < MINIMUM_KEY_SIZE) {
            cred.secret.copyOf(MINIMUM_KEY_SIZE)
        } else {
            cred.secret
        }
        val keyTlv = byteArrayOf(typeByte.toByte(), cred.digits.toByte()) + secret
        val imf = initialMovingFactor(cred)
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, cred.ykName.toByteArray(Charsets.UTF_8))
            writeTlv(TAG_KEY, keyTlv)
            // An HOTP account's starting counter (an otpauth URI's `counter=`),
            // as YKOATH's initial moving factor: four bytes, big-endian. Left out
            // when it is 0, the applet's default, so such a PUT is unchanged.
            if (imf != 0L) writeTlv(TAG_IMF, ByteArray(4) { ((imf ushr (24 - 8 * it)) and 0xFF).toByte() })
        }.toByteArray()
        val resp = transport.transceive(Apdu.build(0x00, INS_PUT, 0x00, 0x00, body))
        if (isCanoKey && resp.sw == SW_CONDITIONS_NOT_SATISFIED) {
            throw OathNameExistsException(cred.ykName)
        }
        requireSuccess(resp, "PUT")
    }

    /**
     * Whether an HOTP account put with [counter] starts at a later code than
     * the service expects: on a CanoKey, which adds one before computing, a
     * counter of 0 can't be stored one below, so the first code is counter 1's.
     */
    fun hotpStartsLate(counter: Long): Boolean = isCanoKey && counter == 0L

    fun delete(name: String) {
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, name.toByteArray(Charsets.UTF_8))
        }.toByteArray()
        val resp = transport.transceive(Apdu.build(0x00, INS_DELETE, 0x00, 0x00, body))
        requireSuccess(resp, "DELETE")
    }

    data class StoredCredential(val name: String, val typeAlgo: Int)

    // --- helpers ---

    /**
     * The initial moving factor [put] sends: an HOTP account's counter, 0 for
     * TOTP. On a CanoKey one less, since it adds one before computing a code
     * ([isCanoKey]); a counter of 0 stays 0 there ([hotpStartsLate]).
     */
    private fun initialMovingFactor(cred: OathCredential): Long {
        if (cred.type != OathCredential.Type.HOTP) return 0
        require(cred.counter in 0..0xFFFF_FFFFL) {
            "An HOTP counter must fit in 4 bytes (0 to 4294967295)"
        }
        return if (isCanoKey && cred.counter > 0) cred.counter - 1 else cred.counter
    }

    /**
     * A locked applet answers every instruction with 6982. Report that as a
     * password prompt rather than a raw status word, so a protected key is not
     * mistaken for a broken or absent one.
     */
    private fun requireSuccess(resp: ResponseApdu, what: String) {
        if (resp.isSuccess) return
        if (resp.sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
            validated = false
            throw OathPasswordRequiredException(selected?.deviceId ?: ByteArray(0))
        }
        throw TransportException("$what SW=${"%04X".format(resp.sw)}")
    }

    private fun decodeResponseCode(data: ByteArray): String {
        // Response: tag (0x76 truncated / 0x75 full) | len | digits | 4-byte code
        var i = 0
        val tag = data[i].toInt() and 0xFF; i++
        val len = data[i].toInt() and 0xFF; i++
        require(tag == TAG_RESPONSE_TRUNC || tag == TAG_RESPONSE_FULL) {
            "unexpected CALCULATE response tag ${"%02X".format(tag)}"
        }
        val digits = data[i].toInt() and 0xFF
        val code =
            ((data[i + 1].toInt() and 0x7F) shl 24) or
            ((data[i + 2].toInt() and 0xFF) shl 16) or
            ((data[i + 3].toInt() and 0xFF) shl 8) or
            (data[i + 4].toInt() and 0xFF)
        var mod = 1; repeat(digits) { mod *= 10 }
        return (code % mod).toString().padStart(digits, '0')
    }

    private fun parseTlvs(data: ByteArray): Map<Int, ByteArray> {
        val map = HashMap<Int, ByteArray>()
        var i = 0
        while (i + 1 < data.size) {
            val tag = data[i].toInt() and 0xFF; i++
            val len = data[i].toInt() and 0xFF; i++
            if (i + len > data.size) break
            map[tag] = data.copyOfRange(i, i + len)
            i += len
        }
        return map
    }

    private fun ByteArrayOutputStream.writeTlv(tag: Int, value: ByteArray) {
        write(tag and 0xFF); write(value.size and 0xFF); write(value)
    }
}

/**
 * A CanoKey refused a PUT because it already holds an account of that name
 * (SW 6985): it doesn't overwrite one. The message is the status word, as
 * every other refused PUT reports it.
 */
class OathNameExistsException(val name: String) : TransportException("PUT SW=6985")
