package com.token2.lkcompanion.token2

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the §1.20 fingerprint capture-poll state machine to the keyroost
 * hardware-tested reference: 80 C5 05 06 01 01 starts the capture (device may
 * answer 0x9100 "in progress"), then the host polls 80 11 00 00 00 while 0x9100
 * until a terminal SW. Also covers the replay/trace case where the start APDU
 * returns 0x9000 directly (no poll), and the never-touched timeout.
 */
class Token2FingerprintPollTest {

    // Build a bare client instance just to reach the pure helper. The transport
    // lambdas are never invoked by pollFingerprintCapture beyond what we pass in.
    private val client = Token2Client.overHidForTest()

    @Test fun start_9100_then_polls_until_9000() {
        val polls = ArrayDeque(listOf(0x9100, 0x9100, 0x9000))
        var pollCount = 0
        val sw = client.pollFingerprintCapture(
            start = { 0x9100 },
            poll = { pollCount++; polls.removeFirst() },
        )
        assertEquals(0x9000, sw)
        assertEquals(3, pollCount)   // polled until the 0x9000
    }

    @Test fun start_9000_directly_no_poll() {
        var pollCount = 0
        val sw = client.pollFingerprintCapture(
            start = { 0x9000 },
            poll = { pollCount++; 0x9000 },
        )
        assertEquals(0x9000, sw)
        assertEquals(0, pollCount)   // capture already satisfied; no poll
    }

    @Test fun never_touched_times_out_as_6FFA() {
        val sw = client.pollFingerprintCapture(
            start = { 0x9100 },
            poll = { 0x9100 },        // sensor never touched
        )
        assertEquals(0x6FFA, sw)
    }

    @Test fun terminal_error_passed_through() {
        val sw = client.pollFingerprintCapture(
            start = { 0x9100 },
            poll = { 0x6982 },        // FP protection not enabled
        )
        assertEquals(0x6982, sw)
    }
}
