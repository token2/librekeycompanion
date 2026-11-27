package com.token2.lkcompanion.canokey

import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.appletSelectionException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Telling a CanoKey apart, and what is sent to a card that isn't one. */
class CanoKeyTest {

    /** A card with [historicalBytes] whose Admin applet, if [admin], answers [answers] by INS/P1. */
    private class AdminCard(
        override val historicalBytes: ByteArray?,
        private val admin: Boolean,
        private val answers: Map<Pair<Int, Int>, ResponseApdu> = CANARY,
    ) : SmartCardTransport {
        val sent = ArrayList<String>()
        override val displayName = "fake"
        override val isConnected = true
        override fun selectApplet(aid: ByteArray): ByteArray {
            sent += "SELECT " + aid.joinToString("") { "%02X".format(it) }
            if (!admin) throw appletSelectionException(aid, 0x6A82)
            return ByteArray(0)
        }
        override fun transceive(command: ByteArray): ResponseApdu {
            val ins = command[1].toInt() and 0xFF
            val p1 = command[2].toInt() and 0xFF
            sent += "INS %02X/%02X".format(ins, p1)
            return answers[ins to p1] ?: ResponseApdu(ByteArray(0), 0x6D00)
        }
        override fun close() = Unit
    }

    @Test
    fun `a canokey on usb reports its firmware, hardware and decimal serial`() {
        val info = CanoKey.probe(AdminCard("Canokey".toByteArray(), admin = true))
        assertEquals(CanoKey.Info("3.1.2", "CanoKey Canary", 439041101L), info)
    }

    @Test
    fun `a card held to a phone with no historical bytes is asked, and is one when it answers`() {
        assertTrue(CanoKey.isCanoKey(AdminCard(ByteArray(0), admin = true)))
    }

    @Test
    fun `a card with no historical bytes and no admin applet gets one select only`() {
        val card = AdminCard(ByteArray(0), admin = false)
        assertNull(CanoKey.probe(card))
        assertEquals(listOf("SELECT F000000000"), card.sent)
    }

    @Test
    fun `a card that answers the select but gives no version is not a canokey`() {
        val card = AdminCard(
            ByteArray(0), admin = true,
            answers = mapOf((0x31 to 0x00) to ResponseApdu("hello".toByteArray(), 0x9000)),
        )
        assertNull(CanoKey.probe(card))
    }

    @Test
    fun `a card that names itself otherwise, or an unknown one, is sent nothing`() {
        for (historical in listOf("YubiKey".toByteArray(), null)) {
            val card = AdminCard(historical, admin = true)
            assertNull(CanoKey.probe(card))
            assertTrue(card.sent.toString(), card.sent.isEmpty())
        }
    }

    @Test
    fun `a serial never written is no serial`() {
        assertNull(CanoKey.parseSerial(byteArrayOf(0, 0, 0, 0)))
        assertNull(CanoKey.parseSerial(byteArrayOf(-1, -1, -1, -1)))
        assertNull(CanoKey.parseSerial(byteArrayOf(1, 2, 3)))
        assertEquals(4294967294L, CanoKey.parseSerial(byteArrayOf(-1, -1, -1, -2)))
    }

    @Test
    fun `firmware versions are read as canokey writes them`() {
        assertEquals("3.1.2", CanoKey.parseFirmwareVersion("3.1.2\u0000".toByteArray()))
        assertEquals("v2.0.1-dev", CanoKey.parseFirmwareVersion("v2.0.1-dev".toByteArray()))
        assertNull(CanoKey.parseFirmwareVersion("Canary".toByteArray()))
        assertNull(CanoKey.parseFirmwareVersion(ByteArray(0)))
    }

    private companion object {
        val CANARY = mapOf(
            (0x31 to 0x00) to ResponseApdu("3.1.2".toByteArray(), 0x9000),
            (0x31 to 0x01) to ResponseApdu("CanoKey Canary".toByteArray(), 0x9000),
            (0x32 to 0x00) to ResponseApdu(byteArrayOf(0x1A, 0x2B, 0x3C, 0x4D), 0x9000),
        )
    }
}
