package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.token2.Token2Client
import com.token2.lkcompanion.token2.Token2Codec
import com.token2.lkcompanion.token2.Token2Exception
import com.token2.lkcompanion.transport.AppletUnavailableException
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Bridges the momentary NFC tap to a browsable UI.
 *
 * NFC sessions exist only for the ~1s the key is on the reader, so we can't keep
 * a live handle while the user reads the screen. Instead the UI ARMS an operation
 * (refresh / add / delete), the user taps the key, and [executeOn] runs the armed
 * op against that transient transport and refreshes the cached entry list.
 *
 * This is the same "arm then tap" model the Token2 reference and YubiKey
 * Authenticator use for NFC.
 */
class Token2Repository {

    sealed class PendingOp {
        object Refresh : PendingOp()
        data class Add(val entry: Token2Codec.Entry, val allowOverwrite: Boolean = false) : PendingOp()
        data class Delete(val app: String, val account: String) : PendingOp()
        /** Read the key's current interface configuration (§6.9). */
        object ReadConfig : PendingOp()
        /**
         * Enable/disable USB interfaces (§6.8). Fields are the desired ENABLED
         * state of each interface; the client enforces the two-interface minimum.
         */
        data class SetInterfaces(
            val fido: Boolean,
            val keyboard: Boolean,
            val ccid: Boolean,
        ) : PendingOp()
    }

    /** Snapshot of which USB interfaces the key currently exposes (§6.9). */
    data class IfaceState(
        val fido: Boolean,
        val keyboard: Boolean,
        val ccid: Boolean,
        /** Model support, so the UI can grey out toggles the key can't offer. */
        val keyboardSupported: Boolean,
        val ccidSupported: Boolean,
        /** §1.11 ext bit 8: key can require a fingerprint for OTP. */
        val otpFingerprintProtectSupported: Boolean = false,
        /** §1.11 cfg bit 4: a fingerprint sensor is present. */
        val fingerprintPresent: Boolean = false,
    )

    /** Result of executing an op against a tapped key. */
    sealed class OpResult {
        data class Success(val message: String, val entries: List<Token2Codec.Entry>) : OpResult()
        data class Failure(val message: String) : OpResult()
        /** Current interface configuration, for the enable/disable dialog. */
        data class Config(val iface: IfaceState) : OpResult()
        /** The key already has an entry with this issuer/account; ask before overwriting. */
        data class DuplicateExists(
            val entry: Token2Codec.Entry,
            val existingLabel: String,
            val entries: List<Token2Codec.Entry>,
        ) : OpResult()
        object NotAToken2Key : OpResult()
        /** Enumerate hit a PIN-protected key; the UI must collect + verify a PIN. */
        data class PinRequired(
            val fingerprintProtectSupported: Boolean = false,
            val fingerprintPresent: Boolean = false,
        ) : OpResult()
        /** A supplied PIN was rejected by the key. retriesLeft if known. */
        data class PinWrong(
            val retriesLeft: Int?,
            val maxRetries: Int?,
            val fingerprintProtectSupported: Boolean = false,
            val fingerprintPresent: Boolean = false,
        ) : OpResult()
        /**
         * PIN accepted, but the key's fingerprint-protected-OTP flag is on and
         * the §1.20 fingerprint check didn't pass (no finger / mismatch / timeout).
         * The UI should ask the user to touch the sensor and re-present the key.
         */
        data class FingerprintRequired(val detail: String) : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.Refresh
        private set

    @Volatile var cachedEntries: List<Token2Codec.Entry> = emptyList()
        private set

    // When set, the next enumerate first opens a verify window with this PIN
    // (protected key). Cleared once consumed. Held only in memory.
    @Volatile private var pendingPin: String? = null

    // When true, the next contact sends lock_otp_pin first to close the device's
    // verify window (needed over USB where the connection — and thus the open
    // window — persists across reads). Cleared after it runs.
    @Volatile private var lockOnNextContact: Boolean = false
    /**
     * Fingerprint-only unlock (§1.20): the key's OTP is fingerprint-protected
     * and the user chose to authorize with a fingerprint instead of the PIN.
     * The capture trace shows the device opens the read/write window on
     * `80 C5 05 06 01 01` alone, with no preceding VERIFY_OTP_PIN.
     */
    @Volatile private var pendingFingerprintOnly: Boolean = false

    /** Supply a PIN to verify on the next read (for a protected key). */
    fun supplyPin(pin: String) { pendingPin = pin }
    fun clearPin() { pendingPin = null; pendingFingerprintOnly = false }
    /** Authorize the next contact with a fingerprint only (no PIN). */
    fun supplyFingerprintOnly() { pendingPin = null; pendingFingerprintOnly = true }
    /** Whether a PIN is currently held (supplied and not yet cleared). */
    fun hasPin(): Boolean = pendingPin != null
    /** Whether some OTP authorization (PIN or fingerprint) is currently armed. */
    fun hasAuth(): Boolean = pendingPin != null || pendingFingerprintOnly
    /** Forget the PIN and request the device window be closed on next contact. */
    fun lockNow() { pendingPin = null; pendingFingerprintOnly = false; lockOnNextContact = true }

    fun arm(op: PendingOp) { pending = op }

    /**
     * Invoked (on the worker thread) right before the key is asked to verify a
     * fingerprint, so the UI can tell the user to touch the sensor now.
     */
    @Volatile var onFingerprintPrompt: (() -> Unit)? = null

    /**
     * Run the armed op against a freshly-tapped transport. Returns a user-facing
     * result and updates [cachedEntries]. Always re-enumerates afterward so the UI
     * reflects the device's true state.
     */
    fun executeOn(transport: SmartCardTransport): OpResult {
        val client = try {
            Token2Client.overNfc(transport)
        } catch (e: AppletUnavailableException) {
            return OpResult.NotAToken2Key
        } catch (e: Exception) {
            return OpResult.Failure("Token2 probe failed: ${e.message ?: e.javaClass.simpleName}")
        }

        val op = pending
        return try {
            when (op) {
                is PendingOp.Refresh -> {
                    val entries = enumerateSafe(client)
                    cachedEntries = entries
                    pending = PendingOp.Refresh
                    OpResult.Success("Refreshed", entries)
                }
                is PendingOp.Add -> {
                    // Authoritative duplicate check: enumerate the key NOW (not the
                    // cache, which may be stale) and match on issuer+account.
                    val current = enumerateSafe(client)
                    val dup = current.firstOrNull { sameIdentity(it, op.entry) }
                    if (dup != null && !op.allowOverwrite) {
                        // Don't write; surface it so the UI can confirm overwrite.
                        cachedEntries = current
                        OpResult.DuplicateExists(op.entry, dup.label, current)
                    } else {
                        if (dup != null) {
                            // Overwrite = delete the existing identity, then write.
                            client.deleteEntry(dup.appName, dup.accountName)
                        }
                        client.writeEntry(op.entry)
                        val entries = enumerateSafe(client)
                        cachedEntries = entries
                        pending = PendingOp.Refresh
                        val verb = if (dup != null) "Replaced" else "Added"
                        OpResult.Success("$verb ${op.entry.label}", entries)
                    }
                }
                is PendingOp.Delete -> {
                    verifyIfPending(client)      // open PIN window first on protected keys
                    client.deleteEntry(op.app, op.account)
                    val entries = enumerateSafe(client)
                    cachedEntries = entries
                    pending = PendingOp.Refresh
                    OpResult.Success("Deleted ${op.app}/${op.account}", entries)
                }
                is PendingOp.ReadConfig -> {
                    val info = client.readConfig()
                    pending = PendingOp.Refresh
                    OpResult.Config(
                        IfaceState(
                            fido = !info.fidoDisabled,
                            keyboard = !info.keyboardHidDisabled,
                            ccid = !info.ccidDisabled,
                            // FIDO is always present on these keys; keyboard/CCID
                            // support come from the capability bytes.
                            keyboardSupported = info.hotpSupported,
                            ccidSupported = info.ccidSupported,
                            otpFingerprintProtectSupported = info.otpFingerprintProtectSupported,
                            fingerprintPresent = info.fingerprintPresent,
                        )
                    )
                }
                is PendingOp.SetInterfaces -> {
                    client.setInterfaces(op.fido, op.keyboard, op.ccid)
                    pending = PendingOp.Refresh
                    OpResult.Success(
                        "Interface configuration updated. Re-plug or re-tap the key for it to take effect.",
                        cachedEntries,
                    )
                }
            }
        } catch (e: Token2Exception.PinNotVerified) {
            val hadPin = pendingPin != null
            clearPin()
            // Learn whether this key can unlock by fingerprint, so the unlock
            // prompt can offer it. Best effort — a byte-0 stub over NFC leaves
            // it false and we simply don't show the fingerprint option.
            val info = try { client.readConfig() } catch (_: Exception) { null }
            val fpCap = info?.hasConfigByte == true && info.raw.size >= 10
            // Also consult the PIN flag: if fingerprint protection is already
            // ENABLED on the key, it self-evidently supports fingerprint unlock,
            // so offer it even when the ext capability byte is conservative or
            // came back as a short stub over this transport.
            val fpFlag = try { client.pinStatus().fpEnable } catch (_: Exception) { null }
            val fpSupported = (fpCap && info!!.otpFingerprintProtectSupported) || (fpFlag == true)
            val fpPresent = (fpCap && info!!.fingerprintPresent) || (fpFlag == true)
            if (hadPin) {
                // Re-read the flag to report how many attempts remain.
                val flag = try { client.pinStatus() } catch (_: Exception) { null }
                OpResult.PinWrong(flag?.retriesLeft, flag?.maxRetries, fpSupported, fpPresent)
            } else OpResult.PinRequired(fpSupported, fpPresent)
        } catch (e: Token2Exception.FingerprintNotVerified) {
            OpResult.FingerprintRequired(e.message ?: "fingerprint not verified")
        } catch (e: Token2Exception.ButtonPressRequired) {
            OpResult.Failure("Touch the key's button to confirm, then tap again.")
        } catch (e: Token2Exception.NotEnoughSpace) {
            OpResult.Failure("No space left on the key for another entry.")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }

    /** Two entries are "the same" if issuer and account match (case-insensitive, trimmed). */
    private fun sameIdentity(a: Token2Codec.Entry, b: Token2Codec.Entry): Boolean =
        a.appName.trim().equals(b.appName.trim(), ignoreCase = true) &&
        a.accountName.trim().equals(b.accountName.trim(), ignoreCase = true)

    /** Cache-based advisory check for the UI before arming (may be stale). */
    fun cachedDuplicateOf(entry: Token2Codec.Entry): Token2Codec.Entry? =
        cachedEntries.firstOrNull { sameIdentity(it, entry) }

    private val Token2Codec.Entry.label: String
        get() = if (appName.isBlank()) accountName else "$appName / $accountName"

    private fun enumerateSafe(client: Token2Client): List<Token2Codec.Entry> {
        verifyIfPending(client)
        return try {
            client.enumerate(System.currentTimeMillis() / 1000)
        } catch (e: Token2Exception.EntryNotFound) {
            emptyList()                          // empty token
        }
    }

    /**
     * If the UI supplied a PIN (protected key), open the verify window on this
     * session before a read/write. A wrong PIN throws PinNotVerified, which
     * propagates to executeOn's handler. On an unprotected key this is a no-op
     * (no PIN supplied).
     */
    private fun verifyIfPending(client: Token2Client) {
        if (lockOnNextContact) {
            client.lockOtpPin()          // close the device window (esp. over USB)
            lockOnNextContact = false
        }
        // Fingerprint-protected OTP means the code can be released by a
        // fingerprint OR the PIN — either one, never both (keyroost #130). So
        // the two paths are mutually exclusive: verify with whichever the user
        // chose, and do NOT chain a fingerprint after a PIN verify.
        val pin = pendingPin
        if (pin != null) {
            client.verifyOtpPin(pin.toByteArray(Charsets.UTF_8))
        } else if (pendingFingerprintOnly) {
            // Fingerprint-only authorization: open the window with the finger
            // alone (no VERIFY_OTP_PIN), as the reference does.
            onFingerprintPrompt?.invoke()
            client.verifyOtpFingerprint()
        }
    }
}
