package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** What PUT sends for an account's starting counter (YKOATH tag 7A). */
class OathAppletPutTest {

    private class RecordingTransport : SmartCardTransport {
        val sent = ArrayList<ByteArray>()
        override val displayName = "fake"
        override val isConnected = true
        override fun selectApplet(aid: ByteArray) = ByteArray(0)
        override fun transceive(command: ByteArray): ResponseApdu {
            sent += command
            return ResponseApdu(ByteArray(0), 0x9000)
        }
        override fun close() = Unit
    }

    private fun put(cred: OathCredential): ByteArray {
        val transport = RecordingTransport()
        OathApplet(transport).put(cred)
        val apdu = transport.sent.single()
        assertEquals(0x01, apdu[1].toInt())                // INS PUT
        return apdu.copyOfRange(5, 5 + (apdu[4].toInt() and 0xFF))
    }

    private fun cred(type: OathCredential.Type, counter: Long) = OathCredential(
        issuer = "Example", account = "alice", secret = ByteArray(20) { it.toByte() },
        type = type, counter = counter,
    )

    @Test
    fun `an hotp account's counter is sent big-endian in tag 7A`() {
        val body = put(cred(OathCredential.Type.HOTP, 0x0102_0304L))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), tlv(body, 0x7A))
    }

    @Test
    fun `a zero counter and a totp account send no counter, as before`() {
        assertNull(tlv(put(cred(OathCredential.Type.HOTP, 0)), 0x7A))
        assertNull(tlv(put(cred(OathCredential.Type.TOTP, 5)), 0x7A))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a counter past four bytes is refused before anything is sent`() {
        OathApplet(RecordingTransport()).put(cred(OathCredential.Type.HOTP, 0x1_0000_0000L))
    }

    private fun tlv(body: ByteArray, tag: Int): ByteArray? {
        var i = 0
        while (i + 1 < body.size) {
            val t = body[i].toInt() and 0xFF
            val len = body[i + 1].toInt() and 0xFF
            if (t == tag) return body.copyOfRange(i + 2, i + 2 + len)
            i += 2 + len
        }
        return null
    }
}
