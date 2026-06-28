package com.token2.lkcompanion.fido.ctap

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport

/** A CTAP2 status code other than success (0x00). */
class CtapError(val code: Int) : Exception("CTAP error 0x${"%02X".format(code)}: ${name(code)}") {
    companion object {
        fun name(c: Int) = when (c) {
            0x31 -> "PIN_INVALID"
            0x32 -> "PIN_BLOCKED"
            0x33 -> "PIN_AUTH_INVALID"
            0x34 -> "PIN_AUTH_BLOCKED"
            0x35 -> "PIN_NOT_SET"
            0x36 -> "PUAT_REQUIRED / PIN_REQUIRED"
            0x37 -> "PIN_POLICY_VIOLATION"
            0x3B -> "NO_CREDENTIALS"
            0x2B -> "KEY_STORE_FULL"
            0x27 -> "CREDENTIAL_EXCLUDED"
            0x2D -> "NOT_ALLOWED"
            0x2E -> "INVALID_OPTION"
            0x19 -> "OPERATION_DENIED"
            else -> "see CTAP spec"
        }
    }
}

/**
 * CTAP2 over the smart-card transport (NFC ISO-DEP / USB CCID).
 *
 * Implements the MANAGEMENT subset only — feature detection, PIN lifecycle,
 * alwaysUv, and discoverable-credential listing/deletion. It deliberately does
 * NOT do makeCredential / getAssertion (those are the credential-provider flow,
 * handled by Authnkey).
 *
 * Crypto (clientPIN) is delegated to [PinUvAuthProtocol], verified against the
 * published CTAP2.1 vectors.
 */
class Ctap2Client(private val wire: Ctap2Wire) {

    /** Convenience: APDU wire over a smart-card transport (NFC / USB CCID). */
    constructor(transport: SmartCardTransport) : this(ApduWire(transport))

    companion object {
        private val FIDO_AID = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)

        // CTAP2 command bytes
        private const val CMD_MAKE_CREDENTIAL = 0x01
        private const val CMD_GET_ASSERTION = 0x02
        private const val CMD_GET_INFO = 0x04
        private const val CMD_CLIENT_PIN = 0x06
        private const val CMD_RESET = 0x07
        private const val CMD_CRED_MGMT = 0x0A          // 0x41 in some preview builds
        private const val CMD_CRED_MGMT_PREVIEW = 0x41
        private const val CMD_CONFIG = 0x0D
        private const val CMD_BIO_ENROLL = 0x09             // authenticatorBioEnrollment
        private const val CMD_BIO_ENROLL_PREVIEW = 0x40     // prototype/preview variant

        // bioEnrollment subcommands (modality = 1 fingerprint)
        private const val BIO_ENROLL_BEGIN = 0x01
        private const val BIO_ENROLL_CAPTURE_NEXT = 0x02
        private const val BIO_ENROLL_CANCEL = 0x03
        private const val BIO_ENUMERATE = 0x04
        private const val BIO_SET_NAME = 0x05
        private const val BIO_REMOVE = 0x06
        private const val BIO_GET_SENSOR_INFO = 0x07
        private const val BIO_MODALITY_FP = 0x01            // fingerprint modality
        private const val PERM_BIO_ENROLL = 0x08            // be (bioEnrollment) permission

        // clientPIN subcommands
        private const val SUB_GET_RETRIES = 0x01
        private const val SUB_GET_KEY_AGREEMENT = 0x02
        private const val SUB_SET_PIN = 0x03
        private const val SUB_CHANGE_PIN = 0x04
        private const val SUB_GET_PIN_TOKEN = 0x05
        private const val SUB_GET_TOKEN_UV_PERM = 0x06
        private const val SUB_GET_UV_RETRIES = 0x07
        private const val SUB_GET_TOKEN_PIN_PERM = 0x09

        // credentialManagement subcommands
        private const val CM_GET_CREDS_META = 0x01
        private const val CM_ENUM_RPS_BEGIN = 0x02
        private const val CM_ENUM_RPS_NEXT = 0x03
        private const val CM_ENUM_CREDS_BEGIN = 0x04
        private const val CM_ENUM_CREDS_NEXT = 0x05
        private const val CM_DELETE_CRED = 0x06

        // authenticatorConfig subcommands
        private const val CFG_TOGGLE_ALWAYS_UV = 0x02

        // permissions bits
        private const val PERM_CRED_MGMT = 0x04
        private const val PERM_AUTH_CFG = 0x20
    }

    fun selectFido() { wire.selectFido() }

    // ---- info ----

    data class Info(
        val versions: List<String>,
        val options: Map<String, Boolean>,
        val pinProtocols: List<Int>,
        val aaguidHex: String?,
        val minPinLength: Int?,
    ) {
        val isFido2 get() = versions.any { it.startsWith("FIDO_2") }
        val clientPinSet get() = options["clientPin"] == true
        val alwaysUv get() = options["alwaysUv"] == true
        val supportsCredMgmt get() = options["credMgmt"] == true || options["credentialMgmtPreview"] == true
        val supportsConfig get() = options["authnrCfg"] == true
        /** True if the key accepts permission-scoped tokens (0x09); else use legacy 0x05. */
        val supportsPinUvAuthToken get() = options["pinUvAuthToken"] == true
        /** Fingerprint enrollment support (CTAP2.1 authenticatorBioEnrollment). */
        val supportsBioEnroll get() =
            options["bioEnroll"] == true || options["userVerificationMgmtPreview"] == true
        /** True if the key uses the preview/prototype bio command (0x40) rather than 0x09. */
        val bioUsesPreview get() =
            options["bioEnroll"] != true && options["userVerificationMgmtPreview"] == true
    }

    @Suppress("UNCHECKED_CAST")
    fun getInfo(): Info {
        selectFido()
        val resp = sendCbor(CMD_GET_INFO, null)
        val m = resp as Map<Int, Any?>
        val versions = (m[1] as? List<*>)?.map { it.toString() } ?: emptyList()
        val options = (m[4] as? Map<*, *>)?.entries
            ?.associate { it.key.toString() to (it.value == true) } ?: emptyMap()
        val protos = (m[6] as? List<*>)?.mapNotNull { (it as? Number)?.toInt() } ?: listOf(1)
        val aaguid = (m[3] as? ByteArray)?.joinToString("") { "%02x".format(it) }
        val minPin = (m[0x0D] as? Number)?.toInt()
        return Info(versions, options, protos, aaguid, minPin)
    }

    // ---- clientPIN ----

    /** Pick the highest mutually-supported PIN/UV protocol. */
    private fun protocolFor(info: Info): PinUvAuthProtocol =
        if (info.pinProtocols.contains(2)) PinUvAuthProtocol.V2() else PinUvAuthProtocol.V1()

    fun getPinRetries(): Int {
        val resp = clientPin(1, SUB_GET_RETRIES, null) as Map<*, *>
        return (resp[3] as Number).toInt()           // retries at key 3
    }

    fun getUvRetries(): Int? = try {
        val resp = clientPin(1, SUB_GET_UV_RETRIES, null) as Map<*, *>
        (resp[5] as? Number)?.toInt()
    } catch (e: Exception) { null }

    /** authenticator's key-agreement public key (COSE EC2) -> raw X,Y. */
    @Suppress("UNCHECKED_CAST")
    private fun getKeyAgreement(proto: PinUvAuthProtocol): Pair<ByteArray, ByteArray> {
        val resp = clientPin(proto.version, SUB_GET_KEY_AGREEMENT, null) as Map<Int, Any?>
        val cose = resp[1] as Map<Int, Any?>
        val x = cose[-2] as ByteArray
        val y = cose[-3] as ByteArray
        return x to y
    }

    /** Set an initial PIN (only when none is configured). PIN is UTF-8, ≥4 chars. */
    fun setPin(newPin: String, info: Info) {
        require(newPin.toByteArray(Charsets.UTF_8).size in 4..63) { "PIN must be 4..63 bytes" }
        val proto = protocolFor(info)
        val (ax, ay) = getKeyAgreement(proto)
        val ss = proto.encapsulate(ax, ay)
        val newPinPadded = padPin(newPin)
        val newPinEnc = ss.encrypt(newPinPadded)
        val pinUvAuthParam = ss.authenticate(newPinEnc)
        val params = linkedMapOf<Int, Any?>(
            1 to proto.version,                       // pinUvAuthProtocol
            2 to SUB_SET_PIN,                         // subCommand
            3 to proto.platformCoseKey(),             // keyAgreement
            4 to pinUvAuthParam,                      // pinUvAuthParam
            5 to newPinEnc,                           // newPinEnc
        )
        sendCbor(CMD_CLIENT_PIN, Cbor.encode(params))
    }

    /** Change an existing PIN. */
    fun changePin(oldPin: String, newPin: String, info: Info) {
        require(newPin.toByteArray(Charsets.UTF_8).size in 4..63) { "PIN must be 4..63 bytes" }
        val proto = protocolFor(info)
        val (ax, ay) = getKeyAgreement(proto)
        val ss = proto.encapsulate(ax, ay)
        val pinHashLeft16 = sha256(oldPin.toByteArray(Charsets.UTF_8)).copyOf(16)
        val pinHashEnc = ss.encrypt(pinHashLeft16)
        val newPinEnc = ss.encrypt(padPin(newPin))
        val pinUvAuthParam = ss.authenticate(newPinEnc + pinHashEnc)
        val params = linkedMapOf<Int, Any?>(
            1 to proto.version,
            2 to SUB_CHANGE_PIN,
            3 to proto.platformCoseKey(),
            4 to pinUvAuthParam,
            5 to newPinEnc,
            6 to pinHashEnc,
        )
        sendCbor(CMD_CLIENT_PIN, Cbor.encode(params))
    }

    /** Obtain a pinUvAuthToken (with permissions, CTAP2.1) for follow-up commands. */
    @Suppress("UNCHECKED_CAST")
    /**
     * Obtain a pinUvAuthToken for follow-up commands.
     *
     * CTAP2.1 keys advertise the `pinUvAuthToken` option and accept the
     * permission-scoped subcommand getPinUvAuthTokenUsingPinWithPermissions (0x09).
     * Older keys (e.g. YubiKeys that only expose `credentialMgmtPreview`) do NOT
     * support 0x09 and reject it with CTAP1_ERR_INVALID_COMMAND (0x01); they need
     * the legacy getPinToken (0x05), which returns a token with implicit
     * permissions. We pick based on the key's advertised option.
     */
    private fun getPinToken(
        pin: String, proto: PinUvAuthProtocol, permissions: Int, supportsPermissions: Boolean,
    ): ByteArray {
        val (ax, ay) = getKeyAgreement(proto)
        val ss = proto.encapsulate(ax, ay)
        val pinHashEnc = ss.encrypt(sha256(pin.toByteArray(Charsets.UTF_8)).copyOf(16))
        val params = if (supportsPermissions) {
            linkedMapOf<Int, Any?>(
                1 to proto.version,
                2 to SUB_GET_TOKEN_PIN_PERM,              // 0x09
                3 to proto.platformCoseKey(),
                6 to pinHashEnc,
                9 to permissions,
            )
        } else {
            linkedMapOf<Int, Any?>(
                1 to proto.version,
                2 to SUB_GET_PIN_TOKEN,                   // 0x05 legacy, no permissions
                3 to proto.platformCoseKey(),
                6 to pinHashEnc,
            )
        }
        val resp = sendCbor(CMD_CLIENT_PIN, Cbor.encode(params)) as Map<Int, Any?>
        val encToken = resp[2] as ByteArray
        return ss.decrypt(encToken)                   // the pinUvAuthToken
    }

    // ---- alwaysUv ----

    /** Toggle the alwaysUv option (requires a PIN token with acfg permission). */
    fun toggleAlwaysUv(pin: String) {
        val info = getInfo()
        require(info.supportsConfig) { "Authenticator doesn't support authenticatorConfig" }
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_AUTH_CFG, info.supportsPinUvAuthToken)
        // pinUvAuthParam = authenticate(token, 0x20 (cmd) || 0xff*32-ish per spec)
        // Per spec §6.11: authenticate over (32 0xff bytes || 0x0d || subCommand)
        val msg = ByteArray(32) { 0xFF.toByte() } + byteArrayOf(CMD_CONFIG.toByte(), CFG_TOGGLE_ALWAYS_UV.toByte())
        val authParam = authenticateWithToken(proto, token, msg)
        val params = linkedMapOf<Int, Any?>(
            1 to CFG_TOGGLE_ALWAYS_UV,                // subCommand
            3 to proto.version,                       // pinUvAuthProtocol
            4 to authParam,                           // pinUvAuthParam
        )
        sendCbor(CMD_CONFIG, Cbor.encode(params))
    }

    // ---- credential management ----

    data class Passkey(
        val rpId: String,
        val userName: String?,
        val userDisplayName: String?,
        val credentialIdB64: String,
        val credentialId: ByteArray,
        /** WebAuthn user handle (user.id), hex; null if absent. */
        val userHandleHex: String? = null,
        /** COSE key algorithm of the credential public key (e.g. -7 = ES256). */
        val algorithm: Int? = null,
        /** credProtect policy (1=optional, 2=optional-with-ID, 3=required); null if absent. */
        val credProtect: Int? = null,
    )

    /** List discoverable credentials (passkeys). Needs the PIN. */
    @Suppress("UNCHECKED_CAST")
    fun listPasskeys(pin: String): List<Passkey> {
        val info = getInfo()
        require(info.supportsCredMgmt) { "Authenticator doesn't support credential management" }
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_CRED_MGMT, info.supportsPinUvAuthToken)
        val cmCmd = if (info.options["credMgmt"] == true) CMD_CRED_MGMT else CMD_CRED_MGMT_PREVIEW

        val result = ArrayList<Passkey>()
        // enumerate RPs
        val rps = enumerateRps(cmCmd, proto, token)
        for (rp in rps) {
            val creds = enumerateCredsForRp(cmCmd, proto, token, rp.second)
            for (c in creds) result.add(c.copy(rpId = rp.first))
        }
        return result
    }

    /** Delete a passkey by credential ID. Needs the PIN. */
    fun deletePasskey(pin: String, credentialId: ByteArray) {
        val info = getInfo()
        require(info.supportsCredMgmt) { "Authenticator doesn't support credential management" }
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_CRED_MGMT, info.supportsPinUvAuthToken)
        val cmCmd = if (info.options["credMgmt"] == true) CMD_CRED_MGMT else CMD_CRED_MGMT_PREVIEW
        // subCommandParams = { 2: { "id": credId, "type": "public-key" } }
        val credDesc = linkedMapOf<Any, Any>("id" to credentialId, "type" to "public-key")
        val subParams = linkedMapOf<Int, Any?>(2 to credDesc)
        val authParam = credMgmtAuth(proto, token, CM_DELETE_CRED, Cbor.encode(subParams))
        val params = linkedMapOf<Int, Any?>(
            1 to CM_DELETE_CRED,
            2 to subParams,
            3 to proto.version,
            4 to authParam,
        )
        sendCbor(cmCmd, Cbor.encode(params))
    }

    @Suppress("UNCHECKED_CAST")
    private fun enumerateRps(cmCmd: Int, proto: PinUvAuthProtocol, token: ByteArray):
            List<Pair<String, ByteArray>> {
        val out = ArrayList<Pair<String, ByteArray>>()
        val authParam = credMgmtAuth(proto, token, CM_ENUM_RPS_BEGIN, null)
        val begin = linkedMapOf<Int, Any?>(1 to CM_ENUM_RPS_BEGIN, 3 to proto.version, 4 to authParam)
        val first = try { sendCbor(cmCmd, Cbor.encode(begin)) as Map<Int, Any?> }
            catch (e: CtapError) { if (e.code == 0x2E || e.code == 0x3B) return emptyList() else throw e }
        val total = (first[5] as? Number)?.toInt() ?: 0
        if (total == 0) return emptyList()
        addRp(first, out)
        repeat(total - 1) {
            val next = linkedMapOf<Int, Any?>(1 to CM_ENUM_RPS_NEXT)
            val r = sendCbor(cmCmd, Cbor.encode(next)) as Map<Int, Any?>
            addRp(r, out)
        }
        return out
    }

    @Suppress("UNCHECKED_CAST")
    private fun addRp(m: Map<Int, Any?>, out: MutableList<Pair<String, ByteArray>>) {
        val rp = m[3] as? Map<*, *> ?: return
        val id = rp["id"]?.toString() ?: return
        val hash = m[4] as? ByteArray ?: ByteArray(0)
        out.add(id to hash)
    }

    @Suppress("UNCHECKED_CAST")
    private fun enumerateCredsForRp(cmCmd: Int, proto: PinUvAuthProtocol, token: ByteArray,
                                    rpIdHash: ByteArray): List<Passkey> {
        val out = ArrayList<Passkey>()
        val subParams = linkedMapOf<Int, Any?>(1 to rpIdHash)
        val authParam = credMgmtAuth(proto, token, CM_ENUM_CREDS_BEGIN, Cbor.encode(subParams))
        val begin = linkedMapOf<Int, Any?>(
            1 to CM_ENUM_CREDS_BEGIN, 2 to subParams, 3 to proto.version, 4 to authParam)
        val first = try { sendCbor(cmCmd, Cbor.encode(begin)) as Map<Int, Any?> }
            catch (e: CtapError) { if (e.code == 0x2E || e.code == 0x3B) return emptyList() else throw e }
        val total = (first[9] as? Number)?.toInt() ?: 0
        if (total == 0) return out
        addCred(first, out)
        repeat(total - 1) {
            val next = linkedMapOf<Int, Any?>(1 to CM_ENUM_CREDS_NEXT)
            val r = sendCbor(cmCmd, Cbor.encode(next)) as Map<Int, Any?>
            addCred(r, out)
        }
        return out
    }

    @Suppress("UNCHECKED_CAST")
    private fun addCred(m: Map<Int, Any?>, out: MutableList<Passkey>) {
        val user = m[6] as? Map<*, *>
        val credId = m[7] as? Map<*, *>
        val id = credId?.get("id") as? ByteArray ?: return
        // publicKey (0x08) is a COSE_Key map; algorithm lives at label 3.
        val algorithm = (m[8] as? Map<*, *>)?.let { cose ->
            (cose[3] as? Number)?.toInt()
        }
        // credProtect (0x0A) policy, if the authenticator reports it.
        val credProtect = (m[0x0A] as? Number)?.toInt()
        val userHandle = (user?.get("id") as? ByteArray)?.joinToString("") { "%02x".format(it) }
        out.add(Passkey(
            rpId = "",                                // filled by caller
            userName = user?.get("name")?.toString(),
            userDisplayName = user?.get("displayName")?.toString(),
            credentialIdB64 = android.util.Base64.encodeToString(
                id, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE),
            credentialId = id,
            userHandleHex = userHandle,
            algorithm = algorithm,
            credProtect = credProtect,
        ))
    }

    /** credMgmt pinUvAuthParam = authenticate(token, subCommand || subCommandParams). */
    private fun credMgmtAuth(proto: PinUvAuthProtocol, token: ByteArray,
                             subCommand: Int, subParamsCbor: ByteArray?): ByteArray {
        val msg = byteArrayOf(subCommand.toByte()) + (subParamsCbor ?: ByteArray(0))
        return authenticateWithToken(proto, token, msg)
    }

    /** HMAC the message under the pinUvAuthToken using the active protocol. */
    private fun authenticateWithToken(proto: PinUvAuthProtocol, token: ByteArray, msg: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(token, "HmacSHA256"))
        val full = mac.doFinal(msg)
        return if (proto.version == 1) full.copyOf(16) else full
    }

    // ---- fingerprint / bio enrollment (CTAP2.1 authenticatorBioEnrollment) ----

    data class FingerprintSensorInfo(
        /** 1 = touch sensor, 2 = swipe sensor (fingerprintKind). */
        val fingerprintKind: Int?,
        /** How many good samples a full enroll needs. */
        val maxSamplesForEnroll: Int?,
        /** Max length (bytes) of a friendly name. */
        val maxFriendlyNameBytes: Int?,
    )

    data class Fingerprint(val templateId: ByteArray, val name: String?) {
        val templateIdHex: String get() = templateId.joinToString("") { "%02x".format(it) }
    }

    /** One step of an in-progress enrollment. */
    data class EnrollSample(
        val templateId: ByteArray,
        /** lastEnrollSampleStatus — 0x00 good; others are feedback (see [sampleStatusText]). */
        val lastStatus: Int,
        /** How many more good samples are still needed (0 = done). */
        val remaining: Int,
    ) {
        val complete: Boolean get() = remaining == 0 && lastStatus == 0x00
    }

    private fun bioCmd(info: Info) = if (info.bioUsesPreview) CMD_BIO_ENROLL_PREVIEW else CMD_BIO_ENROLL

    /** getFingerprintSensorInfo — no auth needed (uses getModality-style framing). */
    @Suppress("UNCHECKED_CAST")
    fun getFingerprintSensorInfo(): FingerprintSensorInfo {
        val info = getInfo()
        require(info.supportsBioEnroll) { "Authenticator doesn't support fingerprint enrollment" }
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP,                 // modality
            2 to BIO_GET_SENSOR_INFO,             // subCommand
        )
        val resp = sendCbor(bioCmd(info), Cbor.encode(params)) as Map<Int, Any?>
        return FingerprintSensorInfo(
            fingerprintKind = (resp[2] as? Number)?.toInt(),
            maxSamplesForEnroll = (resp[3] as? Number)?.toInt(),
            maxFriendlyNameBytes = (resp[8] as? Number)?.toInt(),
        )
    }

    /** enumerateEnrollments — list enrolled fingerprints. Needs the PIN. */
    @Suppress("UNCHECKED_CAST")
    fun listFingerprints(pin: String): List<Fingerprint> {
        val info = getInfo()
        require(info.supportsBioEnroll) { "Authenticator doesn't support fingerprint enrollment" }
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_BIO_ENROLL, info.supportsPinUvAuthToken)
        val authParam = bioAuth(proto, token, BIO_ENUMERATE, null)
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP,
            2 to BIO_ENUMERATE,
            4 to proto.version,
            5 to authParam,
        )
        val resp = try { sendCbor(bioCmd(info), Cbor.encode(params)) as Map<Int, Any?> }
            catch (e: CtapError) { if (e.code == 0x2E) return emptyList() else throw e } // 0x2E = no templates
        val templates = resp[7] as? List<*> ?: return emptyList()
        return templates.mapNotNull { t ->
            val m = t as? Map<*, *> ?: return@mapNotNull null
            val id = m[1] as? ByteArray ?: return@mapNotNull null
            Fingerprint(id, m[2]?.toString())
        }
    }

    /** setFriendlyName — rename an enrolled fingerprint. Needs the PIN. */
    fun renameFingerprint(pin: String, templateId: ByteArray, newName: String) {
        val info = getInfo()
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_BIO_ENROLL, info.supportsPinUvAuthToken)
        val subParams = linkedMapOf<Int, Any?>(1 to templateId, 2 to newName)
        val authParam = bioAuth(proto, token, BIO_SET_NAME, Cbor.encode(subParams))
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP,
            2 to BIO_SET_NAME,
            3 to subParams,
            4 to proto.version,
            5 to authParam,
        )
        sendCbor(bioCmd(info), Cbor.encode(params))
    }

    /** removeEnrollment — delete an enrolled fingerprint. Needs the PIN. */
    fun removeFingerprint(pin: String, templateId: ByteArray) {
        val info = getInfo()
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_BIO_ENROLL, info.supportsPinUvAuthToken)
        val subParams = linkedMapOf<Int, Any?>(1 to templateId)
        val authParam = bioAuth(proto, token, BIO_REMOVE, Cbor.encode(subParams))
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP,
            2 to BIO_REMOVE,
            3 to subParams,
            4 to proto.version,
            5 to authParam,
        )
        sendCbor(bioCmd(info), Cbor.encode(params))
    }

    /**
     * An open fingerprint-enrollment session. enrollBegin starts it (first touch);
     * call [captureNext] for each subsequent touch until [EnrollSample.complete].
     * The PIN token is held for the life of the session. Call [cancel] to abort.
     */
    inner class EnrollSession internal constructor(
        private val info: Info,
        private val proto: PinUvAuthProtocol,
        private val token: ByteArray,
        val templateId: ByteArray,
    ) {
        /** Capture the next sample (user touches the sensor again). */
        @Suppress("UNCHECKED_CAST")
        fun captureNext(timeoutMs: Int = 10_000): EnrollSample {
            val subParams = linkedMapOf<Int, Any?>(1 to templateId, 3 to timeoutMs)
            val authParam = bioAuth(proto, token, BIO_ENROLL_CAPTURE_NEXT, Cbor.encode(subParams))
            val params = linkedMapOf<Int, Any?>(
                1 to BIO_MODALITY_FP,
                2 to BIO_ENROLL_CAPTURE_NEXT,
                3 to subParams,
                4 to proto.version,
                5 to authParam,
            )
            val resp = sendCbor(bioCmd(info), Cbor.encode(params)) as Map<Int, Any?>
            return EnrollSample(
                templateId = templateId,
                lastStatus = (resp[5] as? Number)?.toInt() ?: 0,
                remaining = (resp[6] as? Number)?.toInt() ?: 0,
            )
        }

        /** Give the just-enrolled fingerprint a friendly name (optional). */
        fun setName(name: String) = renameFingerprintWith(proto, token, info, templateId, name)

        /** Abort an in-progress enrollment. */
        fun cancel() {
            val params = linkedMapOf<Int, Any?>(1 to BIO_MODALITY_FP, 2 to BIO_ENROLL_CANCEL)
            runCatching { sendCbor(bioCmd(info), Cbor.encode(params)) }
        }
    }

    /**
     * Begin enrolling a new fingerprint. Returns the session plus the first sample
     * result (the first touch happens during enrollBegin). Needs the PIN.
     */
    @Suppress("UNCHECKED_CAST")
    fun enrollBegin(pin: String, timeoutMs: Int = 10_000): Pair<EnrollSession, EnrollSample> {
        val info = getInfo()
        require(info.supportsBioEnroll) { "Authenticator doesn't support fingerprint enrollment" }
        val proto = protocolFor(info)
        val token = getPinToken(pin, proto, PERM_BIO_ENROLL, info.supportsPinUvAuthToken)
        // enrollBegin subCommandParams: only timeout (3). pinUvAuthParam over modality||subCmd||params.
        val subParams = linkedMapOf<Int, Any?>(3 to timeoutMs)
        val authParam = bioAuth(proto, token, BIO_ENROLL_BEGIN, Cbor.encode(subParams))
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP,
            2 to BIO_ENROLL_BEGIN,
            3 to subParams,
            4 to proto.version,
            5 to authParam,
        )
        val resp = sendCbor(bioCmd(info), Cbor.encode(params)) as Map<Int, Any?>
        val templateId = resp[4] as? ByteArray
            ?: throw CtapError(0xFF)   // spec requires templateId in enrollBegin response
        val sample = EnrollSample(
            templateId = templateId,
            lastStatus = (resp[5] as? Number)?.toInt() ?: 0,
            remaining = (resp[6] as? Number)?.toInt() ?: 0,
        )
        return EnrollSession(info, proto, token, templateId) to sample
    }

    private fun renameFingerprintWith(
        proto: PinUvAuthProtocol, token: ByteArray, info: Info,
        templateId: ByteArray, newName: String,
    ) {
        val subParams = linkedMapOf<Int, Any?>(1 to templateId, 2 to newName)
        val authParam = bioAuth(proto, token, BIO_SET_NAME, Cbor.encode(subParams))
        val params = linkedMapOf<Int, Any?>(
            1 to BIO_MODALITY_FP, 2 to BIO_SET_NAME, 3 to subParams,
            4 to proto.version, 5 to authParam,
        )
        sendCbor(bioCmd(info), Cbor.encode(params))
    }

    /** bio pinUvAuthParam = authenticate(token, modality || subCommand || subCommandParams). */
    private fun bioAuth(proto: PinUvAuthProtocol, token: ByteArray,
                        subCommand: Int, subParamsCbor: ByteArray?): ByteArray {
        val msg = byteArrayOf(BIO_MODALITY_FP.toByte(), subCommand.toByte()) +
            (subParamsCbor ?: ByteArray(0))
        return authenticateWithToken(proto, token, msg)
    }

    /** Human-readable text for a lastEnrollSampleStatus feedback code (CTAP2.1 §12.3). */
    fun sampleStatusText(code: Int): String = when (code) {
        0x00 -> "Good sample captured"
        0x01 -> "Too high — center your finger"
        0x02 -> "Too low — center your finger"
        0x03 -> "Too left — center your finger"
        0x04 -> "Too right — center your finger"
        0x05 -> "Too fast — hold still"
        0x06 -> "Too slow — move a little"
        0x07 -> "Poor quality — clean finger & sensor"
        0x08 -> "Too skewed — straighten your finger"
        0x09 -> "Too short — cover more of the sensor"
        0x0A -> "Merge failure — try again"
        0x0B -> "Already exists — already enrolled"
        0x0C -> "No user activity"
        0x0D -> "No finger detected — touch the sensor"
        else -> "Touch the sensor again"
    }

    // ---- transport plumbing ----

    private fun clientPin(protoVer: Int, sub: Int, extra: Map<Int, Any?>?): Any? {
        val params = linkedMapOf<Int, Any?>(1 to protoVer, 2 to sub)
        extra?.let { params.putAll(it) }
        return sendCbor(CMD_CLIENT_PIN, Cbor.encode(params))
    }

    /**
     * Send a CTAP2 command through the active wire (APDU for NFC/CCID, CTAPHID for
     * USB HID) and return the decoded CBOR body. The CTAP status byte (first
     * response byte) is checked: 0x00 = success.
     */
    /**
     * authenticatorReset (CTAP2 0x07). Erases ALL credentials/passkeys and clears
     * the PIN, returning the authenticator to a factory state. Irreversible.
     *
     * Most authenticators only honor reset within a short window after power-up
     * (typically ~10s) and require a user-presence touch; otherwise they return
     * CTAP2_ERR_NOT_ALLOWED (0x30). Takes no parameters.
     */
    fun reset() {
        sendCbor(CMD_RESET, null)
    }

    private fun sendCbor(command: Int, cborParams: ByteArray?): Any? {
        val body = wire.send(command, cborParams ?: ByteArray(0))
        if (body.isEmpty()) throw CtapError(0xFF)
        val status = body[0].toInt() and 0xFF
        if (status != 0x00) throw CtapError(status)
        if (body.size == 1) return emptyMap<Int, Any?>()
        return Cbor.decode(body.copyOfRange(1, body.size))
    }

    private fun sha256(b: ByteArray) =
        java.security.MessageDigest.getInstance("SHA-256").digest(b)

    private fun padPin(pin: String): ByteArray {
        // newPin is UTF-8, zero-padded to at least 64 bytes (CTAP requires ≥64).
        val raw = pin.toByteArray(Charsets.UTF_8)
        val padded = ByteArray(maxOf(64, ((raw.size + 15) / 16) * 16))
        System.arraycopy(raw, 0, padded, 0, raw.size)
        return padded
    }
}
