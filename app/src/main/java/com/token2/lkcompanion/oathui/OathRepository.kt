package com.token2.lkcompanion.oathui

import com.token2.lkcompanion.oath.FeitianOtpApplet
import com.token2.lkcompanion.oath.FeitianTouchTimeoutException
import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.oath.OathCredential
import com.token2.lkcompanion.oath.OathPassword
import com.token2.lkcompanion.oath.OathPasswordIncorrectException
import com.token2.lkcompanion.oath.OathPasswordRequiredException
import com.token2.lkcompanion.transport.AppletSelectionFailedException
import com.token2.lkcompanion.transport.AppletUnavailableException
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * Arm-then-tap repository for smart-card OTP applets. YKOATH is probed first;
 * Feitian OTP is probed when YKOATH does not answer its SELECT with 9000
 * (see [detectBackend]).
 */
class OathRepository {

    enum class BackendKind(
        val displayName: String,
        val allowedImportDigits: Set<Int>?,
    ) {
        YKOATH("OATH", null),
        FEITIAN("Feitian OTP", setOf(6, 8));

        fun normalizeImportedDigits(importedDigits: Int): Int = when (this) {
            YKOATH -> 6
            FEITIAN -> importedDigits
        }
    }

    /** Unified display row rendered by [OathEntryAdapter]. */
    data class Display(
        val name: String,
        val protocolName: String,
        val issuer: String,
        val account: String,
        val code: String?,
        val isTotp: Boolean,
        val period: Int,
        val backend: BackendKind,
        val generatedAtSeconds: Long?,
        val touchRequired: Boolean,
    )

    sealed class PendingOp {
        object Refresh : PendingOp()
        data class Add(
            val cred: OathCredential,
            val allowOverwrite: Boolean = false,
            val expectedBackend: BackendKind? = null,
        ) : PendingOp()
        data class Delete(val entry: Display) : PendingOp()
        data class Calculate(val entry: Display) : PendingOp()
        data class CleanupReplacement(
            val staleEntries: List<Display>,
            val account: String,
        ) : PendingOp()
    }

    sealed class OpResult {
        data class Success(
            val message: String,
            val entries: List<Display>,
            val backend: BackendKind,
        ) : OpResult()
        data class Failure(val message: String) : OpResult()
        data class TouchTimeout(val message: String) : OpResult()
        data class DuplicateExists(
            val existingLabel: String,
            val cred: OathCredential,
            val entries: List<Display>,
        ) : OpResult()
        /**
         * The OATH applet is password protected and no valid password is known.
         * The armed operation is kept: supply the password with
         * [rememberPassword] and present the key again to resume it.
         */
        data class PasswordRequired(
            val deviceIdHex: String,
            val wrongPassword: Boolean,
        ) : OpResult()
        object NotAnOathKey : OpResult()
    }

    private data class Stored(
        val name: String,
        val protocolName: String,
        val type: OathCredential.Type,
        val period: Int,
    ) {
        val isTotp: Boolean get() = type == OathCredential.Type.TOTP
    }

    private sealed class Backend(val kind: BackendKind) {
        abstract fun list(): List<Stored>
        abstract fun put(credential: OathCredential)
        abstract fun delete(stored: Stored)
        abstract fun calculate(stored: Stored, unixSeconds: Long): String
        abstract fun protocolName(credential: OathCredential): String

        class Ykoath(private val applet: OathApplet) : Backend(BackendKind.YKOATH) {
            override fun list(): List<Stored> = applet.list().map {
                val type = if ((it.typeAlgo and 0xF0) == 0x20) {
                    OathCredential.Type.TOTP
                } else {
                    OathCredential.Type.HOTP
                }
                val periodPrefix = if (type == OathCredential.Type.TOTP) {
                    parsePeriodPrefix(it.name)
                } else {
                    null
                }
                Stored(
                    periodPrefix?.second ?: it.name,
                    it.name,
                    type,
                    periodPrefix?.first ?: 30,
                )
            }

            override fun put(credential: OathCredential) = applet.put(credential)

            override fun delete(stored: Stored) = applet.delete(stored.protocolName)

            override fun calculate(stored: Stored, unixSeconds: Long): String =
                applet.calculate(stored.protocolName, unixSeconds, stored.period)

            override fun protocolName(credential: OathCredential): String = credential.ykName

            private fun parsePeriodPrefix(name: String): Pair<Int, String>? {
                val slash = name.indexOf('/')
                if (slash <= 0 || slash == name.lastIndex) return null
                val period = name.substring(0, slash).toIntOrNull()
                    ?.takeIf { it > 0 } ?: return null
                return period to name.substring(slash + 1)
            }
        }

        class Feitian(private val applet: FeitianOtpApplet) : Backend(BackendKind.FEITIAN) {
            override fun list(): List<Stored> = applet.list().map {
                Stored(it.name, it.protocolName, it.type, it.period)
            }

            override fun put(credential: OathCredential) = applet.put(credential)

            override fun delete(stored: Stored) =
                applet.delete(stored.protocolName)

            override fun calculate(stored: Stored, unixSeconds: Long): String =
                applet.calculate(
                    stored.protocolName, stored.type, stored.period, unixSeconds
                )

            override fun protocolName(credential: OathCredential): String =
                FeitianOtpApplet.protocolName(credential)
        }
    }

    /**
     * Derived access keys by device id, for the lifetime of this connection
     * only (see [forgetPasswords]). Caching the derived key rather than the
     * password keeps the plaintext out of memory after derivation, and lets a
     * re-tap resume an armed operation without prompting again.
     */
    private val accessKeys = HashMap<String, ByteArray>()

    @Volatile private var pending: PendingOp = PendingOp.Refresh
    @Volatile private var cached: List<Display> = emptyList()
    @Volatile private var cachedBackend: BackendKind? = null
    @Volatile private var executing = false

    @Synchronized
    fun tryArm(op: PendingOp): Boolean = tryArmLocked(op)

    private fun tryArmLocked(op: PendingOp): Boolean {
        if (executing || pending !is PendingOp.Refresh) return false
        pending = op
        return true
    }

    /** Request a normal read without discarding a queued or retryable operation. */
    @Synchronized
    fun requestRefresh(): Boolean {
        if (executing || pending !is PendingOp.Refresh) return false
        return true
    }

    /** True when the next tap belongs to OATH/Feitian and must not probe Token2. */
    @Synchronized
    fun hasPendingOperation(): Boolean = pending !is PendingOp.Refresh

    /** Explicitly discard a queued or retryable operation while no APDU is running. */
    @Synchronized
    fun cancelPending(): Boolean {
        if (executing) return false
        pending = PendingOp.Refresh
        return true
    }
    val cachedEntries get() = cached
    val activeBackend get() = cachedBackend

    fun noteDetectedBackend(backend: BackendKind) {
        cachedBackend = backend
    }

    @Synchronized
    fun clearCache(): Boolean {
        if (executing) return false
        cached = emptyList()
        cachedBackend = null
        return true
    }

    /** Derive and cache the access key for [deviceIdHex] from a typed password. */
    @Synchronized
    fun rememberPassword(deviceIdHex: String, password: String) {
        accessKeys[deviceIdHex] =
            OathPassword.deriveAccessKey(password, OathPassword.fromHex(deviceIdHex))
    }

    /** Drop every cached access key (key removed, or the user asked to lock). */
    @Synchronized
    fun forgetPasswords() {
        accessKeys.values.forEach { it.fill(0) }
        accessKeys.clear()
    }

    @Synchronized
    fun hasPassword(deviceIdHex: String): Boolean = accessKeys.containsKey(deviceIdHex)

    @Synchronized
    private fun accessKeyFor(deviceIdHex: String): ByteArray? = accessKeys[deviceIdHex]

    @Synchronized
    private fun forgetPassword(deviceIdHex: String) {
        accessKeys.remove(deviceIdHex)?.fill(0)
    }

    /**
     * Unlock a freshly selected applet with a cached password, if one is known.
     * Returns false when the applet stays locked. Used by read-only probes (the
     * Info tab) that should degrade to "locked" rather than prompt.
     */
    fun tryUnlock(applet: OathApplet, info: OathApplet.AppletInfo): Boolean = try {
        unlockOrThrow(applet, info)
        true
    } catch (_: OathPasswordRequiredException) {
        false
    } catch (_: OathPasswordIncorrectException) {
        false
    }

    private fun unlockOrThrow(applet: OathApplet, info: OathApplet.AppletInfo) {
        if (!info.challengeRequired) return
        val deviceIdHex = OathPassword.toHex(info.deviceId)
        val key = accessKeyFor(deviceIdHex)
            ?: throw OathPasswordRequiredException(info.deviceId)
        try {
            applet.validate(key)
        } catch (e: OathPasswordIncorrectException) {
            // The password changed on the key, or was cached from a different
            // key with the same id. Never keep retrying a rejected key.
            forgetPassword(deviceIdHex)
            throw e
        }
    }

    /** Clear data for a detached key without discarding replacement recovery. */
    @Synchronized
    fun onTransportDisconnected() {
        cached = emptyList()
        cachedBackend = null
        if (!executing && pending !is PendingOp.CleanupReplacement) {
            pending = PendingOp.Refresh
        }
    }

    fun executeOn(transport: SmartCardTransport): OpResult {
        val op = synchronized(this) {
            if (executing) return OpResult.Failure("OTP operation already in progress")
            executing = true
            pending
        }
        return try {
            val backend = try {
                detectBackend(transport)
            } catch (e: OathPasswordRequiredException) {
                // Keep the armed operation: it resumes once the password arrives.
                return OpResult.PasswordRequired(OathPassword.toHex(e.deviceId), false)
            } catch (e: OathPasswordIncorrectException) {
                return OpResult.PasswordRequired(OathPassword.toHex(e.deviceId), true)
            } catch (e: Exception) {
                resetAfterProbeFailure()
                return OpResult.Failure(e.message ?: e.javaClass.simpleName)
            } ?: run {
                resetAfterProbeFailure()
                return OpResult.NotAnOathKey
            }

            cachedBackend = backend.kind
            try {
                when (op) {
                is PendingOp.Refresh -> {
                    val entries = readAll(
                        backend, calculateCodes = backend.kind == BackendKind.YKOATH
                    )
                    pending = PendingOp.Refresh
                    OpResult.Success("Read ${backend.kind.displayName}", entries, backend.kind)
                }

                is PendingOp.Add -> {
                    op.expectedBackend?.let { expected ->
                        if (backend.kind != expected) {
                            throw TransportException(
                                "The connected key uses ${backend.kind.displayName}, not " +
                                    expected.displayName
                            )
                        }
                    }
                    // Mutation preflight must not CALCULATE Feitian entries: that
                    // would consume the user's short touch window before PUT.
                    val existing = readAll(
                        backend, calculateCodes = backend.kind != BackendKind.FEITIAN
                    )
                    val replacementProtocolName = backend.protocolName(op.cred)
                    val duplicates = existing.filter {
                        (it.issuer.trim().equals(op.cred.issuer.orEmpty().trim(), true) &&
                            it.account.trim().equals(op.cred.account.trim(), true)) ||
                            it.protocolName == replacementProtocolName
                    }
                    if (duplicates.isNotEmpty() && !op.allowOverwrite) {
                        pending = PendingOp.Refresh
                        return OpResult.DuplicateExists(
                            displayLabel(duplicates.first()), op.cred, existing
                        )
                    }
                    val directOverwrite = duplicates.any {
                        it.protocolName == replacementProtocolName
                    }
                    putAndVerify(backend, op.cred, directOverwrite)
                    val staleEntries = duplicates.filter {
                        it.protocolName != replacementProtocolName
                    }
                    if (staleEntries.isNotEmpty()) {
                        val cleanup = PendingOp.CleanupReplacement(
                            staleEntries,
                            op.cred.account,
                        )
                        pending = cleanup
                        finishReplacementCleanup(backend, cleanup)
                    } else {
                        pending = PendingOp.Refresh
                        val entries = readAll(
                            backend, calculateCodes = backend.kind != BackendKind.FEITIAN
                        )
                        val verb = if (duplicates.isEmpty()) "Added" else "Replaced"
                        OpResult.Success(
                            "$verb ${op.cred.account} on ${backend.kind.displayName}",
                            entries,
                            backend.kind,
                        )
                    }
                }

                is PendingOp.Delete -> {
                    if (op.entry.backend != backend.kind) {
                        throw TransportException(
                            "The connected key uses ${backend.kind.displayName}, not " +
                                op.entry.backend.displayName
                        )
                    }
                    deleteAndVerify(backend, op.entry.toStored())
                    pending = PendingOp.Refresh
                    OpResult.Success(
                        "Deleted from ${backend.kind.displayName}",
                        readAll(
                            backend,
                            calculateCodes = backend.kind != BackendKind.FEITIAN,
                        ),
                        backend.kind,
                    )
                }

                is PendingOp.Calculate -> {
                    if (op.entry.backend != backend.kind) {
                        throw TransportException(
                            "The connected key uses ${backend.kind.displayName}, not " +
                                op.entry.backend.displayName
                        )
                    }
                    val now = System.currentTimeMillis() / 1000
                    val code = backend.calculate(op.entry.toStored(), now)
                    val entries = cached.map { entry ->
                        if (entry.backend == backend.kind &&
                            entry.protocolName == op.entry.protocolName) {
                            entry.copy(
                                code = code,
                                generatedAtSeconds = now,
                                touchRequired = false,
                            )
                        } else {
                            entry
                        }
                    }
                    cached = entries
                    pending = PendingOp.Refresh
                    OpResult.Success(
                        "Calculated ${displayLabel(op.entry)}",
                        entries,
                        backend.kind,
                    )
                }

                is PendingOp.CleanupReplacement ->
                    finishReplacementCleanup(backend, op)
                }
            } catch (e: OathPasswordRequiredException) {
                // The applet re-locked mid-operation (e.g. the channel was reset).
                // Keep the pending operation so the retry does not repeat a
                // mutation the key may already have applied.
                OpResult.PasswordRequired(OathPassword.toHex(e.deviceId), false)
            } catch (e: OathPasswordIncorrectException) {
                OpResult.PasswordRequired(OathPassword.toHex(e.deviceId), true)
            } catch (e: FeitianTouchTimeoutException) {
                // Keep the pending operation intact so the UI can retry without
                // asking the user to re-enter a credential or confirm deletion.
                OpResult.TouchTimeout(e.message ?: "Touch was not detected")
            } catch (e: TransportException) {
                // A replacement PUT may already be committed. Keep its cleanup
                // phase so the next connection can reconcile with LIST before
                // deciding whether another DELETE is necessary.
                if (pending !is PendingOp.CleanupReplacement) {
                    pending = PendingOp.Refresh
                }
                OpResult.Failure(e.message ?: "OTP error")
            } catch (e: Exception) {
                pending = PendingOp.Refresh
                OpResult.Failure(e.message ?: e.javaClass.simpleName)
            }
        } finally {
            executing = false
        }
    }

    private fun resetAfterProbeFailure() {
        if (pending !is PendingOp.CleanupReplacement) {
            pending = PendingOp.Refresh
        }
    }

    private fun finishReplacementCleanup(
        backend: Backend,
        op: PendingOp.CleanupReplacement,
    ): OpResult {
        if (op.staleEntries.any { it.backend != backend.kind }) {
            val expected = op.staleEntries.first { it.backend != backend.kind }.backend
            throw TransportException(
                "The connected key uses ${backend.kind.displayName}, not " +
                    expected.displayName
            )
        }

        // A transport can fail after the key accepted DELETE but before its
        // response reaches us. LIST is side-effect free, so reconcile first and
        // never repeat a DELETE that the key has already applied.
        val presentProtocolNames = backend.list()
            .mapTo(HashSet<String>()) { it.protocolName }
        var remaining = op.staleEntries.filter {
            it.protocolName in presentProtocolNames
        }
        pending = PendingOp.CleanupReplacement(remaining, op.account)

        while (remaining.isNotEmpty()) {
            val stale = remaining.first()
            // Save the exact remaining phase before each DELETE. A timeout then
            // retries only this cleanup and never repeats the confirmed PUT.
            pending = PendingOp.CleanupReplacement(remaining, op.account)
            deleteAndVerify(backend, stale.toStored())
            remaining = remaining.drop(1)
        }
        pending = PendingOp.Refresh
        return OpResult.Success(
            "Replaced ${op.account} on ${backend.kind.displayName}",
            readAll(backend, calculateCodes = backend.kind != BackendKind.FEITIAN),
            backend.kind,
        )
    }

    /**
     * SELECT is the capability probe: YKOATH first, then Feitian.
     *
     * A card that does not host YKOATH is not obliged to say 6A82. If it refuses
     * the YKOATH AID with another status word (a Feitian key answers 6700), that
     * must not end the probe before the Feitian applet has been tried.
     *
     * The refusal is kept, and it is what the user gets unless the Feitian applet
     * answers 9000. So the one outcome that differs from "stop at the YKOATH
     * refusal" is a key that then selects the Feitian applet; every other
     * combination of answers reports exactly what it reported before.
     */
    private fun detectBackend(transport: SmartCardTransport): Backend? {
        val ykoath = OathApplet(transport)
        var ykoathRefusal: AppletSelectionFailedException? = null
        val ykoathInfo = try {
            ykoath.select()
        } catch (_: AppletUnavailableException) {
            null
        } catch (e: AppletSelectionFailedException) {
            ykoathRefusal = e
            null
        }
        if (ykoathInfo != null) {
            // SELECT succeeds on a password-protected applet too, so unlock here:
            // otherwise the first LIST/CALCULATE fails with SW 6982.
            unlockOrThrow(ykoath, ykoathInfo)
            return Backend.Ykoath(ykoath)
        }

        val feitian = FeitianOtpApplet(transport)
        try {
            feitian.select()
            return Backend.Feitian(feitian)
        } catch (_: AppletUnavailableException) {
            ykoathRefusal?.let { throw it }
            return null
        } catch (e: AppletSelectionFailedException) {
            // Refused here as well: the earlier YKOATH refusal stays the error.
            throw ykoathRefusal ?: e
        }
    }

    private fun readAll(
        backend: Backend,
        calculateCodes: Boolean = true,
    ): List<Display> {
        val now = System.currentTimeMillis() / 1000
        val out = ArrayList<Display>()
        for (stored in backend.list()) {
            val (issuer, account) = splitName(stored.name, backend.kind)
            var touchRequired = !calculateCodes && backend.kind == BackendKind.FEITIAN
            val code = if (!stored.isTotp || !calculateCodes) {
                null
            } else try {
                backend.calculate(stored, now)
            } catch (_: FeitianTouchTimeoutException) {
                touchRequired = true
                null
            } catch (_: Exception) {
                // Keep the remaining YKOATH credentials visible when one entry
                // is touch-protected, locked, or malformed.
                null
            }
            out.add(
                Display(
                    stored.name,
                    stored.protocolName,
                    issuer,
                    account,
                    code,
                    stored.isTotp,
                    stored.period,
                    backend.kind,
                    if (code != null) now else null,
                    touchRequired,
                )
            )
        }
        cached = out
        return out
    }

    /**
     * Some Feitian firmware applies PUT/DELETE but still returns 6984. LIST is
     * side-effect free and does not require touch, so reconcile the final state
     * before offering a retry that could repeat an already-applied mutation.
     */
    private fun putAndVerify(
        backend: Backend,
        credential: OathCredential,
        directOverwrite: Boolean,
    ) {
        try {
            backend.put(credential)
        } catch (timeout: FeitianTouchTimeoutException) {
            // LIST cannot distinguish the old secret from a same-name overwrite.
            // Keep the operation pending and require an explicit retry.
            if (directOverwrite) throw timeout
            val expectedProtocolName = backend.protocolName(credential)
            val applied = try {
                backend.list().any { it.protocolName == expectedProtocolName }
            } catch (_: Exception) {
                false
            }
            if (!applied) throw timeout
        }
    }

    private fun deleteAndVerify(backend: Backend, stored: Stored) {
        try {
            backend.delete(stored)
        } catch (timeout: FeitianTouchTimeoutException) {
            val applied = try {
                backend.list().none { it.protocolName == stored.protocolName }
            } catch (_: Exception) {
                false
            }
            if (!applied) throw timeout
        }
    }

    private fun splitName(name: String, backend: BackendKind): Pair<String, String> {
        val separator = if (backend == BackendKind.FEITIAN) "_#_" else ":"
        val index = name.indexOf(separator)
        return if (index >= 0) {
            name.substring(0, index) to name.substring(index + separator.length)
        } else {
            "" to name
        }
    }

    private fun Display.toStored(): Stored = Stored(
        name,
        protocolName,
        if (isTotp) OathCredential.Type.TOTP else OathCredential.Type.HOTP,
        period,
    )

    private fun displayLabel(entry: Display): String =
        if (entry.issuer.isBlank()) entry.account else "${entry.issuer} / ${entry.account}"
}
