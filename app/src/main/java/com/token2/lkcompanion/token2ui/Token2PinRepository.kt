package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.token2.Token2Client
import com.token2.lkcompanion.token2.Token2Exception
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Arm/tap bridge for the OTP-PIN (privacy-protection) commands. These run ONLY
 * over the CCID/NFC transport (the OTP applet answers them with 6A86 over
 * USB-HID), so callers must hand [executeOn] a CCID/NFC-backed client.
 */
class Token2PinRepository {

    sealed class PendingOp {
        object Status : PendingOp()
        data class SetPin(val pin: String) : PendingOp()
        data class VerifyPin(val pin: String) : PendingOp()
        data class ChangePin(val current: String, val new: String) : PendingOp()
        data class RemovePin(val current: String) : PendingOp()
        /**
         * Switch fingerprint-protected OTP on/off (§1.14 EncConfig / §1.20).
         * Needs the current PIN: the flag rides on VERIFY_OTP_PIN.
         */
        data class SetFingerprintProtection(val pin: String, val enable: Boolean) : PendingOp()
    }

    sealed class OpResult {
        data class Status(
            val flag: Token2Client.PinFlag,
            /** §1.11 ext bit 8, or null when the config block didn't come back. */
            val fingerprintProtectSupported: Boolean?,
            /** §1.11 cfg bit 4: the key has a fingerprint sensor at all. */
            val fingerprintPresent: Boolean?,
        ) : OpResult()
        data class Success(val message: String) : OpResult()
        /** Wrong PIN or window not open; retriesLeft is the fresh count if known. */
        data class WrongPin(val retriesLeft: Int?) : OpResult()
        /** PIN locked out — erase-all is the only recovery. */
        object Blocked : OpResult()
        /** Firmware lacks the feature (pre-R3.4), or a PIN command failed. */
        data class Unsupported(val detail: String) : OpResult()
        /** Command run over a transport that can't carry PIN commands. */
        object WrongTransport : OpResult()
        /** Enabling FP protection needs an enrolled fingerprint; none is present. */
        object NoFingerprintEnrolled : OpResult()
        data class Failure(val message: String) : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.Status
        private set

    fun arm(op: PendingOp) { pending = op }

    /** Run the armed op against a CCID/NFC-backed client. */
    fun executeOn(client: Token2Client): OpResult {
        return try {
            when (val op = pending) {
                is PendingOp.Status -> {
                    val flag = client.pinStatus()
                    // Best effort: the config block may be a byte-0 stub over NFC.
                    val info = try { client.readConfig() } catch (_: Exception) { null }
                    val hasCfg = info?.hasConfigByte == true && info.raw.size >= 10
                    OpResult.Status(
                        flag,
                        fingerprintProtectSupported = if (hasCfg) info!!.otpFingerprintProtectSupported else null,
                        fingerprintPresent = if (hasCfg) info!!.fingerprintPresent else null,
                    )
                }
                is PendingOp.SetPin -> {
                    client.setOtpPin(op.pin.toByteArray(Charsets.UTF_8))
                    OpResult.Success("OTP PIN set.")
                }
                is PendingOp.VerifyPin -> {
                    client.verifyOtpPin(op.pin.toByteArray(Charsets.UTF_8))
                    OpResult.Success("PIN verified — codes unlocked.")
                }
                is PendingOp.ChangePin -> {
                    client.changeOtpPin(
                        op.current.toByteArray(Charsets.UTF_8),
                        op.new.toByteArray(Charsets.UTF_8),
                    )
                    OpResult.Success("OTP PIN changed.")
                }
                is PendingOp.RemovePin -> {
                    client.removeOtpPin(op.current.toByteArray(Charsets.UTF_8))
                    OpResult.Success("OTP PIN removed.")
                }
                is PendingOp.SetFingerprintProtection -> {
                    client.verifyOtpPin(op.pin.toByteArray(Charsets.UTF_8), fpEnable = op.enable)
                    // Don't leave the verify window open behind the user's back.
                    client.lockOtpPin()
                    OpResult.Success(
                        if (op.enable) "Fingerprint protection enabled — a fingerprint is now required to read OTP codes."
                        else "Fingerprint protection disabled.")
                }
            }
        } catch (e: Token2Exception.PinNotVerified) {
            // Try to report retries-left by re-reading status (best effort).
            val retries = try { client.pinStatus().retriesLeft } catch (_: Exception) { null }
            OpResult.WrongPin(retries)
        } catch (e: Token2Exception.PinBlocked) {
            OpResult.Blocked
        } catch (e: Token2Exception.PinUnsupported) {
            OpResult.Unsupported(e.message ?: "SW=${"%04X".format(e.sw)}")
        } catch (e: Token2Exception.NoFingerprintEnrolled) {
            OpResult.NoFingerprintEnrolled
        } catch (e: Token2Exception.PinTransportUnavailable) {
            OpResult.WrongTransport
        } catch (e: Token2Exception.PinWrongState) {
            OpResult.Failure("Command not allowed in the current PIN state.")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }
}
