package com.token2.lkcompanion.oathui

import com.token2.lkcompanion.canokey.CanoKey
import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.oath.OathCredential
import com.token2.lkcompanion.transport.ResponseApdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.appletSelectionException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replacing an account on a CanoKey, which refuses a name it holds (6985). */
class OathRepositoryCanoKeyTest {

    /**
     * An OATH applet holding "Example:alice" (TOTP) while [held]. [canokey]
     * gives it a CanoKey's ATR and Admin applet. PUTs answer [putAnswers] in turn.
     */
    private class OathCard(
        private val canokey: Boolean,
        private val putAnswers: ArrayDeque<Int>,
        var held: Boolean = true,
    ) : SmartCardTransport {
        val log = ArrayList<String>()
        private var selected = ""
        override val historicalBytes: ByteArray? =
            if (canokey) "Canokey".toByteArray() else null
        override val displayName = "fake"
        override val isConnected = true

        override fun selectApplet(aid: ByteArray): ByteArray {
            val hex = aid.joinToString("") { "%02X".format(it) }
            val known = hex == OATH || (canokey && hex == ADMIN)
            if (!known) throw appletSelectionException(aid, 0x6A82)
            selected = hex
            return ByteArray(0)
        }

        override fun transceive(command: ByteArray): ResponseApdu {
            val ins = command[1].toInt() and 0xFF
            if (selected == ADMIN) {
                return if (ins == 0x31) ResponseApdu("3.1.2".toByteArray(), 0x9000)
                else ResponseApdu(ByteArray(0), 0x6D00)
            }
            return when (ins) {
                0xA1 -> {
                    log += "LIST"
                    val name = "Example:alice".toByteArray()
                    val entry = byteArrayOf(0x72, (name.size + 1).toByte(), 0x21) + name
                    ResponseApdu(if (held) entry else ByteArray(0), 0x9000)
                }
                0x01 -> {
                    val sw = putAnswers.removeFirst()
                    log += "PUT %04X".format(sw)
                    if (sw == 0x9000) held = true
                    ResponseApdu(ByteArray(0), sw)
                }
                0x02 -> {
                    log += "DELETE"
                    held = false
                    ResponseApdu(ByteArray(0), 0x9000)
                }
                // CALCULATE: the codes don't matter here.
                else -> ResponseApdu(ByteArray(0), 0x6A80)
            }
        }

        override fun close() = Unit
    }

    private val cred = OathCredential(
        issuer = "Example", account = "alice", secret = ByteArray(20) { 7 },
        type = OathCredential.Type.TOTP,
    )

    private fun replace(card: OathCard): Pair<OathRepository, OathRepository.OpResult> {
        val repo = OathRepository()
        assertTrue(repo.tryArm(OathRepository.PendingOp.Add(cred, allowOverwrite = true)))
        return repo to repo.executeOn(card)
    }

    @Test
    fun `a canokey's account is deleted, then put again`() {
        val card = OathCard(canokey = true, putAnswers = ArrayDeque(listOf(0x6985, 0x9000)))
        val (repo, result) = replace(card)
        assertTrue(result.toString(), result is OathRepository.OpResult.Success)
        assertEquals(listOf("LIST", "PUT 6985", "LIST", "DELETE", "PUT 9000", "LIST"), card.log)
        assertFalse(repo.hasPendingOperation())
    }

    @Test
    fun `when the second put fails, the add stays armed for the next tap`() {
        val card = OathCard(canokey = true, putAnswers = ArrayDeque(listOf(0x6985, 0x6A84)))
        val (repo, result) = replace(card)
        assertTrue(result.toString(), result is OathRepository.OpResult.Failure)
        result as OathRepository.OpResult.Failure
        assertTrue(result.message, result.message.contains("Present the key again"))
        assertTrue(repo.hasPendingOperation())

        // The next tap finds the name free, so a plain PUT saves the account.
        val retry = OathCard(
            canokey = true, putAnswers = ArrayDeque(listOf(0x9000)), held = false,
        )
        assertTrue(repo.executeOn(retry) is OathRepository.OpResult.Success)
        assertEquals(listOf("LIST", "PUT 9000", "LIST"), retry.log)
        assertFalse(repo.hasPendingOperation())
    }

    @Test
    fun `another key's 6985 deletes nothing`() {
        val card = OathCard(canokey = false, putAnswers = ArrayDeque(listOf(0x6985)))
        val (repo, result) = replace(card)
        assertTrue(result.toString(), result is OathRepository.OpResult.Failure)
        assertEquals(listOf("LIST", "PUT 6985"), card.log)
        assertFalse(repo.hasPendingOperation())
    }

    private companion object {
        val OATH = OathApplet.AID.joinToString("") { "%02X".format(it) }
        val ADMIN = CanoKey.ADMIN_AID.joinToString("") { "%02X".format(it) }
    }
}
