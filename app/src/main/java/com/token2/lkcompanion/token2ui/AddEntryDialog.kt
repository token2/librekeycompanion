package com.token2.lkcompanion.token2ui

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.Toast
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.token2.lkcompanion.R
import com.token2.lkcompanion.oath.Base32
import com.token2.lkcompanion.oath.OathCore.HashAlgo
import com.token2.lkcompanion.token2.Token2Codec

/**
 * Collects a new OTP entry — by scanning a QR code, pasting an `otpauth://` URI,
 * or filling the fields in directly — and returns a validated [Token2Codec.Entry].
 *
 * A scanned/pasted URI POPULATES the individual fields (issuer, account, secret)
 * and the algorithm/period selectors so the user can review and adjust before
 * writing. Algorithm defaults to SHA1; period defaults to 30s.
 *
 * SHA256 detection: prefer the URI's `algorithm=` parameter; if absent, fall back
 * to a case-insensitive scan of the whole QR payload for "sha256" (catches vendor
 * QRs that bake the algorithm into a label or use a non-standard format).
 */
object AddEntryDialog {

    private val ALGO_OPTIONS = listOf("SHA1", "SHA256")
    private val PERIOD_OPTIONS = listOf("30", "60")

    /** Live handle so the host can push a scan result back into the open dialog. */
    class Handle internal constructor(
        private val uriField: EditText,
        private val appField: EditText,
        private val acctField: EditText,
        private val secretField: EditText,
        private val algoSpinner: Spinner,
        private val periodSpinner: Spinner,
    ) {
        /** Parse a scanned/pasted otpauth payload and fill every field. */
        fun applyScannedUri(raw: String) {
            uriField.setText(raw)
            val p = parseOtpauth(raw) ?: return
            if (p.issuer != null) appField.setText(p.issuer)
            acctField.setText(p.account)
            secretField.setText(p.secretBase32)
            algoSpinner.setSelection(if (p.sha256) 1 else 0)
            periodSpinner.setSelection(if (p.period == 60) 1 else 0)
        }
    }

    fun show(
        context: Context,
        onScanRequested: ((Handle) -> Unit)? = null,
        onReady: (Token2Codec.Entry) -> Unit,
    ) {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_add_entry, null)
        val uriField = view.findViewById<EditText>(R.id.fieldUri)
        val appField = view.findViewById<EditText>(R.id.fieldApp)
        val acctField = view.findViewById<EditText>(R.id.fieldAccount)
        val secretField = view.findViewById<EditText>(R.id.fieldSecret)
        val algoSpinner = view.findViewById<Spinner>(R.id.spinnerAlgo)
        val periodSpinner = view.findViewById<Spinner>(R.id.spinnerPeriod)
        val scanButton = view.findViewById<Button>(R.id.btnScanQr)

        algoSpinner.adapter = ArrayAdapter(context,
            android.R.layout.simple_spinner_dropdown_item, ALGO_OPTIONS)
        periodSpinner.adapter = ArrayAdapter(context,
            android.R.layout.simple_spinner_dropdown_item, PERIOD_OPTIONS)

        val handle = Handle(uriField, appField, acctField, secretField,
            algoSpinner, periodSpinner)
        if (onScanRequested != null) {
            scanButton.setOnClickListener { onScanRequested(handle) }
        } else {
            scanButton.visibility = View.GONE
        }

        MaterialAlertDialogBuilder(context)
            .setTitle("Add OTP entry")
            .setView(view)
            .setPositiveButton("Add") { _, _ ->
                val algo = if (algoSpinner.selectedItemPosition == 1)
                    HashAlgo.SHA256 else HashAlgo.SHA1
                val period = if (periodSpinner.selectedItemPosition == 1) 60 else 30
                val entry = buildManual(
                    appField.text.toString(),
                    acctField.text.toString(),
                    secretField.text.toString(),
                    algo, period)
                if (entry == null) {
                    Toast.makeText(context,
                        "Need an account and a valid base32 secret.",
                        Toast.LENGTH_LONG).show()
                } else {
                    onReady(entry)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // --- parsing & building ---

    /** Parsed otpauth fields (transport-agnostic; no android.net.Uri dependency). */
    data class Parsed(
        val issuer: String?,
        val account: String,
        val secretBase32: String,
        val sha256: Boolean,
        val period: Int,
        val digits: Int,
        val isHotp: Boolean,
    )

    /**
     * Parse an otpauth:// URI by hand (so it's unit-testable without Android).
     * Returns null if it's not a usable otpauth URI with a secret.
     */
    fun parseOtpauth(raw: String): Parsed? {
        val s = raw.trim()
        if (!s.startsWith("otpauth://", ignoreCase = true)) return null
        val afterScheme = s.substring("otpauth://".length)
        val isHotp = afterScheme.startsWith("hotp", ignoreCase = true)
        val slash = afterScheme.indexOf('/')
        if (slash < 0) return null
        val rest = afterScheme.substring(slash + 1)
        val qIdx = rest.indexOf('?')
        val label = if (qIdx >= 0) rest.substring(0, qIdx) else rest
        val query = if (qIdx >= 0) rest.substring(qIdx + 1) else ""

        val labelDecoded = urlDecode(label)
        val labelIssuer = if (labelDecoded.contains(":"))
            labelDecoded.substringBefore(":").trim() else null
        val account = (if (labelDecoded.contains(":"))
            labelDecoded.substringAfter(":") else labelDecoded).trim()

        val params = HashMap<String, String>()
        for (kv in query.split("&")) {
            val i = kv.indexOf('=')
            if (i > 0) params[kv.substring(0, i).lowercase()] = urlDecode(kv.substring(i + 1))
        }
        val secret = params["secret"] ?: return null
        val issuer = params["issuer"]?.takeIf { it.isNotBlank() } ?: labelIssuer

        // SHA256: prefer algorithm= param; else case-insensitive scan of whole payload.
        val algoParam = params["algorithm"]
        val sha256 = if (algoParam != null)
            algoParam.uppercase() in setOf("SHA256", "SHA-256")
        else
            s.lowercase().contains("sha256")

        val period = params["period"]?.toIntOrNull() ?: 30
        val digits = params["digits"]?.toIntOrNull() ?: 6

        return Parsed(issuer, account, secret, sha256, period, digits, isHotp)
    }

    /** Build an entry from the (possibly user-edited) manual fields + selectors. */
    fun buildManual(app: String, account: String, secret: String,
                    algo: HashAlgo, period: Int): Token2Codec.Entry? {
        if (account.isBlank() || secret.isBlank()) return null
        val decoded = runCatching { Base32.decode(secret) }.getOrNull() ?: return null
        val entry = Token2Codec.Entry(
            type = Token2Codec.TYPE_TOTP,
            algorithm = if (algo == HashAlgo.SHA256)
                Token2Codec.ALG_SHA256 else Token2Codec.ALG_SHA1,
            timestep = period,
            codeLength = 6,
            buttonRequired = false,
            appName = app.trim(),
            accountName = account.trim(),
            seed = decoded,
        )
        return entry.takeIf { valid(it, decoded) }
    }

    private fun valid(e: Token2Codec.Entry, seed: ByteArray): Boolean =
        e.accountName.toByteArray(Charsets.US_ASCII).size in 1..64 &&
        e.appName.toByteArray(Charsets.US_ASCII).size in 0..64 &&
        seed.size in 1..64 &&
        e.codeLength in 4..10 &&
        e.timestep in 1..0xFFFF

    private fun urlDecode(s: String): String =
        try { java.net.URLDecoder.decode(s, "UTF-8") } catch (e: Exception) { s }
}
