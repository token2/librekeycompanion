package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A CanoKey's OATH rules: the counter one below, and a name it holds refused. */
class OathAppletCanoKeyTest {

    private class Card(private val putStatus: Int = 0x9000) : SmartCardTransport {
        val sent = ArrayList<ByteArray>()
        override val displayName = "fake"
        override val isConnected = true
        override fun selectApplet(aid: ByteArray) = ByteArray(0)
        override fun transceive(command: ByteArray): ResponseApdu {
            sent += command
            return ResponseApdu(ByteArray(0), putStatus)
        }
        override fun close() = Unit
    }

    private fun hotp(counter: Long) = OathCredential(
        issuer = null, account = "h", secret = ByteArray(20), type = OathCredential.Type.HOTP,
        counter = counter,
    )

    private fun imfSent(canokey: Boolean, counter: Long): ByteArray? {
        val card = Card()
        OathApplet(card, isCanoKey = canokey).put(hotp(counter))
        val apdu = card.sent.single()
        val body = apdu.copyOfRange(5, 5 + (apdu[4].toInt() and 0xFF))
        var i = 0
        while (i + 1 < body.size) {
            val len = body[i + 1].toInt() and 0xFF
            if (body[i].toInt() and 0xFF == 0x7A) return body.copyOfRange(i + 2, i + 2 + len)
            i += 2 + len
        }
        return null
    }

    @Test
    fun `a canokey stores one below the first code's counter`() {
        assertArrayEquals(byteArrayOf(0, 0, 0, 4), imfSent(canokey = true, counter = 5))
        // Counter 1 is stored as 0, the default, so no tag goes.
        assertNull(imfSent(canokey = true, counter = 1))
        // Every other key gets the counter itself.
        assertArrayEquals(byteArrayOf(0, 0, 0, 5), imfSent(canokey = false, counter = 5))
    }

    @Test
    fun `only a canokey starts an hotp account from counter 0 late`() {
        assertTrue(OathApplet(Card(), isCanoKey = true).hotpStartsLate(0))
        assertFalse(OathApplet(Card(), isCanoKey = true).hotpStartsLate(5))
        assertFalse(OathApplet(Card(), isCanoKey = false).hotpStartsLate(0))
    }

    @Test(expected = OathNameExistsException::class)
    fun `a canokey's 6985 to a put is a name it already holds`() {
        OathApplet(Card(putStatus = 0x6985), isCanoKey = true).put(hotp(0))
    }

    @Test
    fun `another key's 6985 stays a plain refusal`() {
        try {
            OathApplet(Card(putStatus = 0x6985), isCanoKey = false).put(hotp(0))
        } catch (e: TransportException) {
            assertFalse(e is OathNameExistsException)
            assertTrue(e.message, e.message!!.contains("6985"))
            return
        }
        throw AssertionError("PUT 6985 was accepted")
    }
}
