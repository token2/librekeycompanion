package com.token2.lkcompanion.token2

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.AlgorithmParameters
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * OTP-PIN ("privacy protection") session crypto for Token2 PIN+ keys.
 *
 * This is the authenticated-ECDH-session layer that sits on top of the plain
 * seed-write ECDH in [Token2Crypto]. It is a byte-for-byte port of the Rust
 * reference (`T2TOTP_Authenticator/src/crypto.rs`). If any construction here
 * diverges from the reference, the device answers 6982 and a wrong PIN is
 * indistinguishable from a wrong implementation — so this file is validated
 * against the reference's own test vectors (see Token2PinCryptoSelfTest).
 *
 * Session-key ladder (all HMAC-SHA256):
 *   shared        = ECDH-P256(hostPriv, devPub).X          (32 bytes)
 *   pu1PRKey      = HMAC(key = 0x00*32, data = shared)
 *   SessionMacKey = HMAC(key = pu1PRKey, data = "TOTP HMAC key" || 0x01)
 *   SessionEncKey = HMAC(key = pu1PRKey, data = "TOTP AES key"  || 0x01)
 */
object Token2PinCrypto {

    /** The two 32-byte session keys derived from a READ_AGREEMENT_PUBKEY exchange. */
    class SessionKeys(val enc: ByteArray, val mac: ByteArray)

    /**
     * A two-step handshake: generate the host keypair, expose its public X||Y to
     * send in READ_AGREEMENT_PUBKEY, then [deriveWith] the device's returned
     * pubkey using the SAME private key. This is what callers need when the send
     * and derive happen as separate APDU round-trips.
     */
    class PendingHandshake internal constructor(
        val hostPubXy: ByteArray,
        private val privateKey: java.security.PrivateKey,
    ) {
        fun deriveWith(deviceAgreementXy: ByteArray): SessionKeys {
            require(deviceAgreementXy.size == 64) { "device agreement pubkey must be 64 bytes" }
            val ecSpec = ecParamSpec()
            val x = java.math.BigInteger(1, deviceAgreementXy.copyOfRange(0, 32))
            val y = java.math.BigInteger(1, deviceAgreementXy.copyOfRange(32, 64))
            val devPub = KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(ECPoint(x, y), ecSpec))
            val shared = KeyAgreement.getInstance("ECDH").run {
                init(privateKey); doPhase(devPub, true); generateSecret()
            }
            return deriveSessionKeys(shared)
        }
    }

    /** Generate a host keypair for a two-step handshake. */
    fun beginHandshake(): PendingHandshake {
        val kpg = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val kp = kpg.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val hostXy = to32(pub.w.affineX) + to32(pub.w.affineY)
        return PendingHandshake(hostXy, kp.private)
    }

    private val rng = SecureRandom()

    // --- primitives ---------------------------------------------------------

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun hmac256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256")); doFinal(data)
        }

    private fun randomIv(): ByteArray = ByteArray(16).also { rng.nextBytes(it) }

    /** AES-256-CBC, PKCS#7 (a.k.a. PKCS5 in JCE) padding. */
    private fun aesCbcPkcs7(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv)); doFinal(data)
        }

    /** AES-256-CBC, NO padding. `data` must be a multiple of 16 bytes. */
    private fun aesCbcNoPad(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv)); doFinal(data)
        }

    /** SessionEncKey encrypt (PKCS#7). */
    fun sessionEncrypt(key: ByteArray, iv: ByteArray, cleartext: ByteArray): ByteArray =
        aesCbcPkcs7(Cipher.ENCRYPT_MODE, key, iv, cleartext)

    /** SessionEncKey decrypt WITHOUT unpadding (raw blocks; for the Rand challenge). */
    fun sessionDecryptRaw(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        if (ciphertext.isEmpty() || ciphertext.size % 16 != 0) return ByteArray(0)
        return aesCbcNoPad(Cipher.DECRYPT_MODE, key, iv, ciphertext)
    }

    /** The 16-byte auth tag form the PIN commands use: HMAC(macKey, data)[:16]. */
    fun sessionAuthTag(macKey: ByteArray, data: ByteArray): ByteArray =
        hmac256(macKey, data).copyOfRange(0, 16)

    /** Constant-time check of a received 16-byte session auth tag. */
    fun verifyAuthTag(macKey: ByteArray, data: ByteArray, tag: ByteArray): Boolean {
        if (tag.size != 16) return false
        val expect = sessionAuthTag(macKey, data)
        var diff = 0
        for (idx in 0 until 16) diff = diff or (expect[idx].toInt() xor tag[idx].toInt())
        return diff == 0
    }

    /** SessionEncKey decrypt WITH PKCS#7 unpadding (for protected enumerate pages). */
    fun sessionDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray =
        aesCbcPkcs7(Cipher.DECRYPT_MODE, key, iv, ciphertext)

    // --- session establishment ---------------------------------------------

    private fun ecParamSpec(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }

    private fun to32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val src = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
        System.arraycopy(src, 0, out, 32 - src.size, src.size)
        return out
    }

    /**
     * Generate a host ephemeral P-256 keypair and derive the session keys against
     * the device's 64-byte agreement pubkey (X||Y, from READ_AGREEMENT_PUBKEY).
     * Returns both the host X||Y to send and the derived keys, so the pubkey sent
     * matches the keys derived.
     */
    /** The HMAC ladder. `sharedX` is the 32-byte ECDH X coordinate. */
    fun deriveSessionKeys(sharedX: ByteArray): SessionKeys {
        val pu1 = hmac256(ByteArray(32), sharedX)
        val macInfo = "TOTP HMAC key".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x01)
        val encInfo = "TOTP AES key".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x01)
        return SessionKeys(
            enc = hmac256(pu1, encInfo),
            mac = hmac256(pu1, macInfo),
        )
    }

    // --- command data-field builders ---------------------------------------

    /**
     * SET_OTP_PIN data field:
     *   NewPin     = 0x07 || 0x64 || pinLen || pin
     *   data       = IV || AES-CBC/PKCS7(EncKey, IV, NewPin) || HMAC(MacKey, enc)[:16]
     */
    fun buildSetPinData(keys: SessionKeys, pin: ByteArray, retry: Int = 0x64): ByteArray {
        val iv = randomIv()
        val newPin = byteArrayOf(0x07, retry.toByte(), pin.size.toByte()) + pin
        val enc = sessionEncrypt(keys.enc, iv, newPin)
        val auth = sessionAuthTag(keys.mac, enc)
        return iv + enc + auth
    }

    /**
     * VERIFY_OTP_PIN data field — nested AES-CBC, no padding:
     *   inner = AES-CBC-nopad(SHA256(pin), SHA256(rand)[:16], rand)
     *   outer = AES-CBC-nopad(EncKey, randomIV, inner)
     *   data  = IV || outer
     * `rand` is the 16-byte challenge recovered from the Lc=0x29 flag read.
     */
    fun buildVerifyPinData(keys: SessionKeys, pin: ByteArray, rand: ByteArray): ByteArray =
        buildVerifyPinData(keys, pin, rand, fpEnable = null)

    /**
     * VERIFY_OTP_PIN with the optional trailing `EncConfig` block (§1.14):
     *   Config    = pkcs7_pad16( FpEnable )        # FpEnable = 0x00 / 0x01
     *   EncConfig = AES-CBC-nopad(EncKey, IV, Config)   # SAME IV as the outer block
     *   data      = IV || outer || EncConfig
     * When present, the applet sets the fingerprint-protected-OTP flag while
     * verifying the PIN (§1.20). `fpEnable == null` omits the block (plain verify).
     */
    fun buildVerifyPinData(
        keys: SessionKeys, pin: ByteArray, rand: ByteArray, fpEnable: Boolean?,
    ): ByteArray {
        require(rand.size == 16) { "rand must be 16 bytes" }
        val pinHash = sha256(pin)                          // 32B -> AES-256 key
        val iv2 = sha256(rand).copyOfRange(0, 16)
        val inner = aesCbcNoPad(Cipher.ENCRYPT_MODE, pinHash, iv2, rand)
        val iv = randomIv()
        val outer = aesCbcNoPad(Cipher.ENCRYPT_MODE, keys.enc, iv, inner)
        if (fpEnable == null) return iv + outer
        val config = pkcs7Pad16(byteArrayOf(if (fpEnable) 0x01 else 0x00))
        val encConfig = aesCbcNoPad(Cipher.ENCRYPT_MODE, keys.enc, iv, config)
        return iv + outer + encConfig
    }

    /**
     * CHANGE_OTP_PIN / remove (remove = empty newPin) data field:
     *   body          = pkcs7_pad16( 0x07 || 0x64 || newLen || newPin )
     *   NewPinEnc     = AES-CBC-nopad(EncKey, IV, body)
     *   OldPinHashEnc = AES-CBC-nopad(EncKey, IV, SHA256(current)[:16])   # SAME IV
     *   NewPinAuth    = HMAC(MacKey, NewPinEnc || OldPinHashEnc)[:16]
     *   data          = IV || NewPinEnc || NewPinAuth || OldPinHashEnc
     */
    fun buildChangePinData(keys: SessionKeys, newPin: ByteArray, currentPin: ByteArray): ByteArray {
        val bodyPlain = byteArrayOf(0x07, 0x64, newPin.size.toByte()) + newPin
        val body = pkcs7Pad16(bodyPlain)
        val iv = randomIv()
        val newPinEnc = aesCbcNoPad(Cipher.ENCRYPT_MODE, keys.enc, iv, body)
        val oldPinHash = sha256(currentPin).copyOfRange(0, 16)      // one block
        val oldPinHashEnc = aesCbcNoPad(Cipher.ENCRYPT_MODE, keys.enc, iv, oldPinHash)
        val auth = sessionAuthTag(keys.mac, newPinEnc + oldPinHashEnc)
        return iv + newPinEnc + auth + oldPinHashEnc
    }

    /**
     * PIN-protected WRITE_SEED data field (used while a verify window is open,
     * when GET_ECDH_PUBKEY is rejected with 6A81):
     *   data = IV || AES-CBC/PKCS7(EncKey, IV, cleartext) || HMAC(MacKey, enc)[:16]
     */
    fun buildProtectedWriteData(keys: SessionKeys, cleartext: ByteArray): ByteArray {
        val iv = randomIv()
        val enc = sessionEncrypt(keys.enc, iv, cleartext)
        val auth = sessionAuthTag(keys.mac, enc)
        return iv + enc + auth
    }

    private fun pkcs7Pad16(data: ByteArray): ByteArray {
        val pad = 16 - (data.size % 16)
        val padByte = pad.toByte()
        return data + ByteArray(pad) { padByte }
    }
}
