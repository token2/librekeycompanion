package com.token2.lkcompanion.token2

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pins the §1.14 `EncConfig` block layout: VERIFY_OTP_PIN data grows from
 * 32 bytes (IV || outer) to 48 (IV || outer || EncConfig), EncConfig is the
 * PKCS#7-padded FpEnable byte encrypted under SessionEncKey with the SAME IV
 * as the outer block, and omitting fpEnable leaves the legacy 32-byte form.
 */
class Token2PinCryptoFingerprintTest {

    private val keys = Token2PinCrypto.deriveSessionKeys(ByteArray(32) { it.toByte() })
    private val pin = "123456".toByteArray()
    private val rand = ByteArray(16) { (0xA0 + it).toByte() }

    private fun aesNoPad(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    @Test fun legacy_verify_is_32_bytes() {
        assertEquals(32, Token2PinCrypto.buildVerifyPinData(keys, pin, rand).size)
        assertEquals(32, Token2PinCrypto.buildVerifyPinData(keys, pin, rand, fpEnable = null).size)
    }

    @Test fun encConfig_appended_with_same_iv_enable() {
        val data = Token2PinCrypto.buildVerifyPinData(keys, pin, rand, fpEnable = true)
        assertEquals(48, data.size)
        val iv = data.copyOfRange(0, 16)
        val config = byteArrayOf(0x01) + ByteArray(15) { 0x0F }   // PKCS#7 pad of 1 byte
        assertArrayEquals(aesNoPad(keys.enc, iv, config), data.copyOfRange(32, 48))
    }

    @Test fun encConfig_appended_with_same_iv_disable() {
        val data = Token2PinCrypto.buildVerifyPinData(keys, pin, rand, fpEnable = false)
        assertEquals(48, data.size)
        val iv = data.copyOfRange(0, 16)
        val config = byteArrayOf(0x00) + ByteArray(15) { 0x0F }
        assertArrayEquals(aesNoPad(keys.enc, iv, config), data.copyOfRange(32, 48))
    }
}
