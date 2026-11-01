package com.token2.lkcompanion.token2ui

import android.content.Context
import android.content.DialogInterface
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
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

    /** Only Feitian imports may change the legacy TOTP/6-digit entry semantics. */
    enum class ImportPolicy { LEGACY_TOTP, FEITIAN }

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
        }

        internal fun applyParsed(p: Parsed) {
            val values = formValues(p)
            appField.setText(values.issuer)
            acctField.setText(values.account)
            secretField.setText(values.secretBase32)
            algoSpinner.setSelection(values.algorithmIndex)
            periodSpinner.setSelection(values.periodIndex)
        }
    }

    fun show(
        context: Context,
        onScanRequested: ((Handle) -> Unit)? = null,
        importPolicy: ImportPolicy = ImportPolicy.LEGACY_TOTP,
        allowedDigits: Set<Int>? = null,
        onReady: (Token2Codec.Entry) -> Boolean,
    ) {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_add_entry, null)
        val uriField = view.findViewById<EditText>(R.id.fieldUri)
        val appField = view.findViewById<EditText>(R.id.fieldApp)
        val acctField = view.findViewById<EditText>(R.id.fieldAccount)
        val secretField = view.findViewById<EditText>(R.id.fieldSecret)
        val algoSpinner = view.findViewById<Spinner>(R.id.spinnerAlgo)
        val periodSpinner = view.findViewById<Spinner>(R.id.spinnerPeriod)
        val scanButton = view.findViewById<Button>(R.id.btnScanQr)
        val requireTouchCheck = view.findViewById<CheckBox>(R.id.checkRequireTouch)

        algoSpinner.adapter = ArrayAdapter(context,
            android.R.layout.simple_spinner_dropdown_item, ALGO_OPTIONS)
        periodSpinner.adapter = ArrayAdapter(context,
            android.R.layout.simple_spinner_dropdown_item, PERIOD_OPTIONS)

        val handle = Handle(uriField, appField, acctField, secretField,
            algoSpinner, periodSpinner)
        uriField.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                parseOtpauth(s?.toString().orEmpty())?.let(handle::applyParsed)
            }
        })
        if (onScanRequested != null) {
            scanButton.setOnClickListener { onScanRequested(handle) }
        } else {
            scanButton.visibility = View.GONE
        }

        val dialog = MaterialAlertDialogBuilder(context)
            .setTitle("Add OTP entry")
            .setView(view)
            .setPositiveButton("Add", null)
            .setNegativeButton("Cancel", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val rawUri = uriField.text.toString().trim()
                val parsedUri = rawUri.takeIf { it.isNotEmpty() }?.let(::parseOtpauth)
                val importFeitianProperties = importPolicy == ImportPolicy.FEITIAN
                if (importFeitianProperties && rawUri.isNotEmpty() && parsedUri == null) {
                    Toast.makeText(context, "Enter a valid OTP Auth URI.", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                val algo = if (algoSpinner.selectedItemPosition == 1)
                    HashAlgo.SHA256 else HashAlgo.SHA1
                val period = if (periodSpinner.selectedItemPosition == 1) 60 else 30
                val isHotp = importFeitianProperties && parsedUri?.isHotp == true
                if (isHotp && parsedUri?.counter != 0L) {
                    Toast.makeText(
                        context,
                        "HOTP import currently supports only an initial counter of 0.",
                        Toast.LENGTH_LONG,
                    ).show()
                    return@setOnClickListener
                }
                val digits = if (importFeitianProperties) parsedUri?.digits ?: 6 else 6
                if (importFeitianProperties && allowedDigits != null && digits !in allowedDigits) {
                    Toast.makeText(
                        context,
                        "This OTP key supports only ${allowedDigits.sorted().joinToString(" or ")} digits.",
                        Toast.LENGTH_LONG,
                    ).show()
                    return@setOnClickListener
                }
                val requireTouch = requireTouchCheck.isChecked
                val entry = if (importFeitianProperties) {
                    buildFeitianEntry(
                        appField.text.toString(),
                        acctField.text.toString(),
                        secretField.text.toString(),
                        algo,
                        period,
                        isHotp = isHotp,
                        digits = digits,
                        counter = if (isHotp) parsedUri?.counter ?: 0L else 0L,
                        buttonRequired = requireTouch,
                    )
                } else {
                    buildManual(
                        appField.text.toString(),
                        acctField.text.toString(),
                        secretField.text.toString(),
                        algo,
                        period,
                        buttonRequired = requireTouch,
                    )
                }
                if (entry == null) {
                    Toast.makeText(context,
                        "Need an account and a valid base32 secret.",
                        Toast.LENGTH_LONG).show()
                } else if (onReady(entry)) {
                    dialog.dismiss()
                }
            }
        }
        dialog.show()
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
        val counter: Long,
    )

    internal data class FormValues(
        val issuer: String,
        val account: String,
        val secretBase32: String,
        val algorithmIndex: Int,
        val periodIndex: Int,
    )

    internal fun formValues(parsed: Parsed): FormValues = FormValues(
        issuer = parsed.issuer.orEmpty(),
        account = parsed.account,
        secretBase32 = parsed.secretBase32,
        algorithmIndex = if (parsed.sha256) 1 else 0,
        periodIndex = if (parsed.period == 60) 1 else 0,
    )

    /**
     * Parse an otpauth:// URI by hand (so it's unit-testable without Android).
     * Returns null if it's not a usable otpauth URI with a secret.
     */
    fun parseOtpauth(raw: String): Parsed? {
        val s = raw.trim()
        if (!s.startsWith("otpauth://", ignoreCase = true)) return null
        val afterScheme = s.substring("otpauth://".length)
        val slash = afterScheme.indexOf('/')
        if (slash < 0) return null
        val type = afterScheme.substring(0, slash).lowercase()
        if (type != "totp" && type != "hotp") return null
        val isHotp = type == "hotp"
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

        val period = params["period"]?.let { it.toIntOrNull() ?: return null } ?: 30
        val digits = params["digits"]?.let { it.toIntOrNull() ?: return null } ?: 6
        val counter = if (isHotp) {
            params["counter"]?.toLongOrNull()?.takeIf { it >= 0 } ?: return null
        } else {
            0L
        }

        return Parsed(issuer, account, secret, sha256, period, digits, isHotp, counter)
    }

    /** Build an entry from the (possibly user-edited) manual fields + selectors. */
    fun buildManual(app: String, account: String, secret: String,
                    algo: HashAlgo, period: Int,
                    buttonRequired: Boolean = false): Token2Codec.Entry? =
        buildEntry(app, account, secret, algo, period, isHotp = false, digits = 6,
            buttonRequired = buttonRequired)

    /** Feitian-only extension for HOTP and 8-digit credentials. */
    private fun buildFeitianEntry(
        app: String,
        account: String,
        secret: String,
        algo: HashAlgo,
        period: Int,
        isHotp: Boolean,
        digits: Int,
        counter: Long,
        buttonRequired: Boolean = false,
    ): Token2Codec.Entry? {
        if (isHotp && counter != 0L) return null
        return buildEntry(app, account, secret, algo, period, isHotp, digits, buttonRequired)
    }

    private fun buildEntry(
        app: String,
        account: String,
        secret: String,
        algo: HashAlgo,
        period: Int,
        isHotp: Boolean,
        digits: Int,
        buttonRequired: Boolean = false,
    ): Token2Codec.Entry? {
        if (account.isBlank() || secret.isBlank()) return null
        val decoded = runCatching { Base32.decode(secret) }.getOrNull() ?: return null
        val entry = Token2Codec.Entry(
            type = if (isHotp) Token2Codec.TYPE_HOTP else Token2Codec.TYPE_TOTP,
            algorithm = if (algo == HashAlgo.SHA256)
                Token2Codec.ALG_SHA256 else Token2Codec.ALG_SHA1,
            timestep = period,
            codeLength = digits,
            buttonRequired = buttonRequired,
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
