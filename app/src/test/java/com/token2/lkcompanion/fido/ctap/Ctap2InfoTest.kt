package com.token2.lkcompanion.fido.ctap

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** getInfo's longTouchForReset (CTAP 2.2, tag 0x18). */
class Ctap2InfoTest {

    /** Answers every command with status 00 and [cbor]. */
    private class FixedWire(private val cbor: ByteArray) : Ctap2Wire {
        override fun send(command: Int, data: ByteArray) = byteArrayOf(0x00) + cbor
        override fun selectFido() = Unit
    }

    private fun info(cbor: String) = Ctap2Client(FixedWire(hex(cbor))).getInfo()

    @Test
    fun `a key that sets longTouchForReset is reported as wanting a long touch`() {
        // {1: ["FIDO_2_1"], 0x18: true}
        assertTrue(info("A2 01 81 68 4649444F5F325F31 18 18 F5").longTouchForReset)
    }

    @Test
    fun `a key without it, or with it false, wants the usual touch`() {
        assertFalse(info("A1 01 81 68 4649444F5F325F31").longTouchForReset)
        assertFalse(info("A2 01 81 68 4649444F5F325F31 18 18 F4").longTouchForReset)
    }

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
