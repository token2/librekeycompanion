package com.token2.lkcompanion.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AtrTest {

    @Test
    fun `a canokey's ccid atr gives its name`() {
        val atr = hex("3BF7110000813 1FE65 43616E6F6B6579 99")
        assertArrayEquals("Canokey".toByteArray(), Atr.historicalBytes(atr))
    }

    @Test
    fun `a yubikey's atr gives its thirteen historical bytes`() {
        val atr = hex("3BFD1300008131FE15 8073C021C057597562694B6579 40")
        assertArrayEquals(hex("8073C021C057597562694B6579"), Atr.historicalBytes(atr))
    }

    @Test
    fun `a contactless atr with none gives none`() {
        assertArrayEquals(ByteArray(0), Atr.historicalBytes(hex("3B80800101")))
    }

    @Test
    fun `an atr shorter than it announces gives nothing`() {
        assertNull(Atr.historicalBytes(hex("3BFD13")))
        assertNull(Atr.historicalBytes(hex("3B")))
    }

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
