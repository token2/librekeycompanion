package com.token2.lkcompanion.oathui

import com.token2.lkcompanion.oath.FeitianOtpApplet
import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.appletSelectionException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Backend probing order: YKOATH first, then Feitian.
 *
 * Regression for "SELECT failed for AID A0000005272101, SW=6700": a Feitian key
 * (OTP applet 1.0.1) answers the YKOATH AID with 6700 rather than 6A82. That
 * refusal used to end the probe, so the Feitian applet on the same key was never
 * tried. Reproduced and fixed on hardware; these tests replay the status words.
 */
class OathRepositoryProbeTest {

    /** SELECT answers come from [selectStatus]; LIST answers from [list]. */
    private class ProbeTransport(
        private val selectStatus: Map<String, Int>,
        private val selectData: Map<String, ByteArray> = emptyMap(),
        private val list: (ByteArray) -> ResponseApdu = { ResponseApdu(ByteArray(0), 0x9000) },
    ) : SmartCardTransport {
        val selected = ArrayList<String>()
        override val displayName: String = "fake"
        override val isConnected: Boolean = true
        override fun selectApplet(aid: ByteArray): ByteArray {
            val key = aid.toHex()
            selected += key
            val sw = selectStatus[key] ?: 0x6A82
            if (sw != 0x9000) throw appletSelectionException(aid, sw)
            return selectData[key] ?: ByteArray(0)
        }
        override fun transceive(command: ByteArray): ResponseApdu = list(command)
        override fun close() = Unit
    }

    private val ykoath = OathApplet.AID.toHex()
    private val feitian = FeitianOtpApplet.AID.toHex()

    // Measured on the key that showed the bug (OTP applet 1.0.1).
    private val feitianFci = hex("5903 010001 5108 12414AF1FB86F67E 7B01 00")
    private val feitianList = hex(
        "520C 11 41534141415F235F414141" +
            "5216 21 33303A7361646173645F235F736164617364617364"
    )

    @Test
    fun `feitian is still probed when the key refuses the ykoath aid with 6700`() {
        val transport = ProbeTransport(
            selectStatus = mapOf(ykoath to 0x6700, feitian to 0x9000),
            selectData = mapOf(feitian to feitianFci),
            list = { cmd ->
                if (cmd[3] == 0xF0.toByte()) ResponseApdu(feitianList, 0x9000)
                else ResponseApdu(ByteArray(0), 0x9000)
            },
        )
        val result = OathRepository().executeOn(transport)

        assertEquals(listOf(ykoath, feitian), transport.selected)
        assertTrue(result.toString(), result is OathRepository.OpResult.Success)
        result as OathRepository.OpResult.Success
        assertEquals(OathRepository.BackendKind.FEITIAN, result.backend)
        assertEquals(
            listOf("ASAAA_#_AAA", "30:sadasd_#_sadasdasd"),
            result.entries.map { it.protocolName },
        )
    }

    @Test
    fun `the ykoath refusal is reported when feitian is absent too`() {
        val transport = ProbeTransport(selectStatus = mapOf(ykoath to 0x6700, feitian to 0x6A82))
        val result = OathRepository().executeOn(transport)

        assertEquals(listOf(ykoath, feitian), transport.selected)
        assertTrue(result.toString(), result is OathRepository.OpResult.Failure)
        val message = (result as OathRepository.OpResult.Failure).message
        assertTrue(message, message.contains("A0000005272101") && message.contains("6700"))
    }

    @Test
    fun `the ykoath refusal is still what is reported when feitian refuses too`() {
        // A key that answers 6700 to every AID it does not host: nothing about
        // its outcome may change, it has no Feitian applet to find.
        val transport = ProbeTransport(selectStatus = mapOf(ykoath to 0x6700, feitian to 0x6700))
        val result = OathRepository().executeOn(transport)

        assertTrue(result.toString(), result is OathRepository.OpResult.Failure)
        val message = (result as OathRepository.OpResult.Failure).message
        assertTrue(message, message.contains("A0000005272101") && message.contains("6700"))
        assertTrue(message, !message.contains("D15600013283260101"))
    }

    @Test
    fun `a feitian refusal is reported as such when ykoath was plainly absent`() {
        val transport = ProbeTransport(selectStatus = mapOf(ykoath to 0x6A82, feitian to 0x6700))
        val result = OathRepository().executeOn(transport)

        assertTrue(result.toString(), result is OathRepository.OpResult.Failure)
        val message = (result as OathRepository.OpResult.Failure).message
        assertTrue(message, message.contains("D15600013283260101") && message.contains("6700"))
    }

    @Test
    fun `a key with neither applet is not an oath key`() {
        val transport = ProbeTransport(selectStatus = mapOf(ykoath to 0x6A82, feitian to 0x6A82))
        assertEquals(OathRepository.OpResult.NotAnOathKey, OathRepository().executeOn(transport))
    }

    @Test
    fun `ykoath wins when it answers and feitian is never selected`() {
        val transport = ProbeTransport(
            selectStatus = mapOf(ykoath to 0x9000, feitian to 0x9000),
            // 79 03 05 04 03 (version) 71 08 <device id>; no 0x74 challenge = no password.
            selectData = mapOf(ykoath to hex("7903 050403 7108 0102030405060708")),
        )
        val result = OathRepository().executeOn(transport)

        assertEquals(listOf(ykoath), transport.selected)
        assertTrue(result.toString(), result is OathRepository.OpResult.Success)
        assertEquals(
            OathRepository.BackendKind.YKOATH,
            (result as OathRepository.OpResult.Success).backend,
        )
    }

}

private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }

private fun hex(s: String): ByteArray =
    Regex("[0-9A-Fa-f]{2}").findAll(s)
        .map { it.value.toInt(16).toByte() }
        .toList()
        .toByteArray()
