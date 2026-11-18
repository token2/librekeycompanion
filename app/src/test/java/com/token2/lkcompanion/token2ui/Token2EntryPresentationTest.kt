package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.token2.Token2Client
import com.token2.lkcompanion.token2.Token2Codec
import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A Token2 row must stop showing a TOTP code once the window it was read in is
 * over. It used to keep the code for as long as the list was on screen, with a
 * 30-second countdown that simply started again, so a code several windows old
 * looked exactly like a fresh one and could still be copied.
 */
class Token2EntryPresentationTest {

    private fun entry(
        timestep: Int = 30,
        code: String? = "123456",
        readAt: Long? = null,
        type: Int = Token2Codec.TYPE_TOTP,
        buttonRequired: Boolean = false,
    ) = Token2Codec.Entry(
        type = type,
        algorithm = Token2Codec.ALG_SHA1,
        timestep = timestep,
        codeLength = 6,
        buttonRequired = buttonRequired,
        appName = "Test",
        accountName = "alice",
        otpCode = code,
        readAtSeconds = readAt,
    )

    // Windows are counted from the epoch, so they start on multiples of the
    // timestep: 1200 starts both a 30 s window (1200..1229) and a 60 s one
    // (1200..1259).

    @Test
    fun `a code is shown while now is in the window it was read in`() {
        val e = entry(readAt = 1_210)
        for (now in longArrayOf(1_210, 1_220, 1_229)) {
            val state = token2EntryUiState(e, now)
            assertTrue("now=$now", state.showCode)
            assertFalse("now=$now", state.expired)
        }
        assertEquals(20, token2EntryUiState(e, 1_210).secondsLeft)
        assertEquals(1, token2EntryUiState(e, 1_229).secondsLeft)
    }

    @Test
    fun `a code is hidden from the first second of the next window`() {
        val e = entry(readAt = 1_210)
        for (now in longArrayOf(1_230, 1_231, 1_259, 1_260, 5_000)) {
            val state = token2EntryUiState(e, now)
            assertFalse("now=$now", state.showCode)
            assertTrue("now=$now", state.expired)
            assertEquals("now=$now", 0, state.secondsLeft)
        }
    }

    @Test
    fun `a code read in the last second of a window expires a second later`() {
        val e = entry(readAt = 1_229)
        assertTrue(token2EntryUiState(e, 1_229).showCode)
        assertTrue(token2EntryUiState(e, 1_230).expired)
    }

    @Test
    fun `a sixty second entry counts down and expires over sixty seconds`() {
        val e = entry(timestep = 60, readAt = 1_220)
        assertEquals(40, token2EntryUiState(e, 1_220).secondsLeft)
        // Still current at 1230, where a 30 s window rolls over.
        assertTrue(token2EntryUiState(e, 1_230).showCode)
        assertEquals(30, token2EntryUiState(e, 1_230).secondsLeft)
        assertEquals(1, token2EntryUiState(e, 1_259).secondsLeft)
        assertTrue(token2EntryUiState(e, 1_260).expired)
    }

    @Test
    fun `entries read together expire by their own periods`() {
        val thirty = entry(timestep = 30, readAt = 1_225)
        val sixty = entry(timestep = 60, readAt = 1_225)
        // 1230 starts a new 30 s window, but the 60 s window runs to 1259.
        assertTrue(token2EntryUiState(thirty, 1_230).expired)
        assertTrue(token2EntryUiState(sixty, 1_230).showCode)
        assertEquals(30, token2EntryUiState(sixty, 1_230).secondsLeft)
    }

    @Test
    fun `an entry without a code has nothing to show or expire`() {
        val state = token2EntryUiState(entry(code = null), 1_000)
        assertFalse(state.showCode)
        assertFalse(state.expired)
    }

    @Test
    fun `a hotp code does not expire with time`() {
        val e = entry(type = Token2Codec.TYPE_HOTP, timestep = 0, readAt = 1_000)
        val state = token2EntryUiState(e, 999_999)
        assertTrue(state.showCode)
        assertFalse(state.expired)
    }

    @Test
    fun `a totp code with no read time is left showing`() {
        val state = token2EntryUiState(entry(readAt = null), 1_210)
        assertTrue(state.showCode)
        assertEquals(20, state.secondsLeft)
    }

    @Test
    fun `a clock that went backwards hides the code`() {
        // The code belongs to window 1230..1259; at 1200 it is not that window's code.
        assertTrue(token2EntryUiState(entry(readAt = 1_235), 1_200).expired)
    }

    // --- the read time has to arrive with the entries ---------------------

    /** Answers every command with [page]; SELECT succeeds with no data. */
    private class PageTransport(private val page: ByteArray) : SmartCardTransport {
        override val displayName: String = "fake"
        override val isConnected: Boolean = true
        override fun selectApplet(aid: ByteArray): ByteArray = ByteArray(0)
        override fun transceive(command: ByteArray): ResponseApdu = ResponseApdu(page, 0x9000)
        override fun close() = Unit
    }

    @Test
    fun `enumerate stamps codes with the timestamp it asked for`() {
        // One TOTP entry "Test" / "alice", 30 s, code 123456 (same page as Token2CodecTest).
        val page = hex("01C1001E0600045465737405616C69636506313233343536")
        val entries = Token2Client.overNfc(PageTransport(page)).enumerate(1_700_000_123)

        val e = entries.single()
        assertEquals("123456", e.otpCode)
        assertEquals(1_700_000_123L, e.readAtSeconds)
        assertTrue(token2EntryUiState(e, 1_700_000_123).showCode)
        assertTrue(token2EntryUiState(e, 1_700_000_123 + 30).expired)
    }

    @Test
    fun `enumerate leaves an entry without a code unstamped`() {
        // HOTP entry: no code tail on the wire.
        val page = hex("00C1001E0600045465737405616C696365")
        val e = Token2Client.overNfc(PageTransport(page)).enumerate(1_700_000_123).single()

        assertNull(e.otpCode)
        assertNull(e.readAtSeconds)
    }

    private fun hex(s: String) = ByteArray(s.length / 2) {
        s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
