package com.token2.lkcompanion.fidoui

import com.token2.lkcompanion.fido.ctap.Ctap2Client
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Arm-then-tap bridge for FIDO2 management, mirroring Token2Repository.
 *
 * The UI arms an operation (read info, set/change PIN, toggle alwaysUv, list or
 * delete passkeys); the next NFC tap runs it via [executeOn] against the CTAP2
 * client and returns a user-facing result.
 *
 * Destructive/credential operations need the PIN, which the UI collects and
 * stashes on the armed op (held only until the tap completes).
 */
class FidoRepository {

    sealed class PendingOp {
        object ReadInfo : PendingOp()
        data class SetPin(val newPin: String) : PendingOp()
        data class ChangePin(val oldPin: String, val newPin: String) : PendingOp()
        data class ToggleAlwaysUv(val pin: String) : PendingOp()
        data class ListPasskeys(val pin: String) : PendingOp()
        data class DeletePasskey(val pin: String, val credentialId: ByteArray) : PendingOp()
        data class ListFingerprints(val pin: String) : PendingOp()
        data class RenameFingerprint(val pin: String, val templateId: ByteArray, val newName: String) : PendingOp()
        data class RemoveFingerprint(val pin: String, val templateId: ByteArray) : PendingOp()
        object ResetFido : PendingOp()
    }

    sealed class OpResult {
        data class Info(val info: Ctap2Client.Info, val pinRetries: Int?, val message: String? = null) : OpResult()
        data class Passkeys(val list: List<Ctap2Client.Passkey>, val message: String? = null) : OpResult()
        data class Fingerprints(val list: List<Ctap2Client.Fingerprint>,
                                val sensor: Ctap2Client.FingerprintSensorInfo? = null,
                                val message: String? = null) : OpResult()
        data class Success(val message: String) : OpResult()
        data class Failure(val message: String) : OpResult()
        object NotFido2 : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.ReadInfo
        private set

    @Volatile var lastInfo: Ctap2Client.Info? = null
        private set

    @Volatile var cachedPasskeys: List<Ctap2Client.Passkey> = emptyList()
        private set

    @Volatile var cachedFingerprints: List<Ctap2Client.Fingerprint> = emptyList()
        private set

    /**
     * Session-only remembered PIN. Held in memory for convenience so consecutive
     * operations don't each re-prompt. NOT persisted to disk — a FIDO2 PIN on
     * disk would be a real security downgrade. Cleared on [forgetPin] or process
     * death.
     */
    @Volatile var rememberedPin: String? = null
        private set

    fun rememberPin(pin: String) { rememberedPin = pin }
    fun forgetPin() { rememberedPin = null }
    val hasRememberedPin get() = rememberedPin != null

    fun arm(op: PendingOp) { pending = op }

    fun executeOn(transport: SmartCardTransport): OpResult =
        executeOnClient(Ctap2Client(transport))

    /** Run against an explicit wire (e.g. CtapHidWire for USB HID FIDO2). */
    fun executeOnWire(wire: com.token2.lkcompanion.fido.ctap.Ctap2Wire): OpResult =
        executeOnClient(Ctap2Client(wire))

    private fun executeOnClient(client: Ctap2Client): OpResult {
        val info = try {
            client.getInfo()
        } catch (e: Exception) {
            return OpResult.NotFido2
        }
        if (!info.isFido2) return OpResult.NotFido2
        lastInfo = info

        return try {
            when (val op = pending) {
                is PendingOp.ReadInfo -> {
                    val retries = if (info.clientPinSet) runCatching { client.getPinRetries() }.getOrNull() else null
                    OpResult.Info(info, retries)
                }
                is PendingOp.SetPin -> {
                    client.setPin(op.newPin, info)
                    pending = PendingOp.ReadInfo
                    val fresh = runCatching { client.getInfo() }.getOrDefault(info)
                    lastInfo = fresh
                    val retries = if (fresh.clientPinSet)
                        runCatching { client.getPinRetries() }.getOrNull() else null
                    OpResult.Info(fresh, retries, message = "PIN set.")
                }
                is PendingOp.ChangePin -> {
                    client.changePin(op.oldPin, op.newPin, info)
                    pending = PendingOp.ReadInfo
                    val fresh = runCatching { client.getInfo() }.getOrDefault(info)
                    lastInfo = fresh
                    val retries = if (fresh.clientPinSet)
                        runCatching { client.getPinRetries() }.getOrNull() else null
                    OpResult.Info(fresh, retries, message = "PIN changed.")
                }
                is PendingOp.ToggleAlwaysUv -> {
                    client.toggleAlwaysUv(op.pin)
                    pending = PendingOp.ReadInfo
                    // Re-read full info so the status panel reflects the new state.
                    val fresh = runCatching { client.getInfo() }.getOrDefault(info)
                    lastInfo = fresh
                    val retries = if (fresh.clientPinSet)
                        runCatching { client.getPinRetries() }.getOrNull() else null
                    OpResult.Info(fresh, retries,
                        message = "alwaysUV is now ${if (fresh.alwaysUv) "ON" else "OFF"}.")
                }
                is PendingOp.ListPasskeys -> {
                    val list = client.listPasskeys(op.pin)
                    cachedPasskeys = list
                    OpResult.Passkeys(list)
                }
                is PendingOp.DeletePasskey -> {
                    client.deletePasskey(op.pin, op.credentialId)
                    val list = runCatching { client.listPasskeys(op.pin) }.getOrDefault(emptyList())
                    cachedPasskeys = list
                    pending = PendingOp.ListPasskeys(op.pin)   // stay on passkey view
                    OpResult.Passkeys(list, message = "Passkey deleted.")
                }
                is PendingOp.ListFingerprints -> {
                    val sensor = runCatching { client.getFingerprintSensorInfo() }.getOrNull()
                    val list = client.listFingerprints(op.pin)
                    cachedFingerprints = list
                    OpResult.Fingerprints(list, sensor)
                }
                is PendingOp.RenameFingerprint -> {
                    client.renameFingerprint(op.pin, op.templateId, op.newName)
                    val list = runCatching { client.listFingerprints(op.pin) }.getOrDefault(emptyList())
                    cachedFingerprints = list
                    pending = PendingOp.ListFingerprints(op.pin)
                    OpResult.Fingerprints(list, message = "Renamed.")
                }
                is PendingOp.RemoveFingerprint -> {
                    client.removeFingerprint(op.pin, op.templateId)
                    val list = runCatching { client.listFingerprints(op.pin) }.getOrDefault(emptyList())
                    cachedFingerprints = list
                    pending = PendingOp.ListFingerprints(op.pin)
                    OpResult.Fingerprints(list, message = "Fingerprint removed.")
                }
                is PendingOp.ResetFido -> {
                    client.reset()
                    // Authenticator is back to factory state: no credentials, no PIN.
                    cachedPasskeys = emptyList()
                    cachedFingerprints = emptyList()
                    forgetPin()
                    pending = PendingOp.ReadInfo
                    OpResult.Success("FIDO2 reset complete. All passkeys erased and PIN removed.")
                }
            }
        } catch (e: com.token2.lkcompanion.fido.ctap.CtapError) {
            OpResult.Failure(friendlyCtap(e.code))
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }

    private fun friendlyCtap(code: Int): String = when (code) {
        0x31 -> "Wrong PIN."
        0x30 -> "Reset not allowed now. Re-tap (or unplug/replug) the key and reset within a few seconds of connecting."
        0x32 -> "PIN is blocked — reset the key to recover."
        0x34 -> "PIN auth blocked — unplug/replug (or re-tap) and try again."
        0x35 -> "No PIN is set on this key yet."
        0x36 -> "This key requires a PIN for that action."
        0x37 -> "PIN doesn't meet the key's policy (length/complexity)."
        0x3B -> "No passkeys stored on this key."
        else -> "CTAP error 0x${"%02X".format(code)} (${com.token2.lkcompanion.fido.ctap.CtapError.name(code)})"
    }
}
