package com.token2.lkcompanion.ui

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.Configuration
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R
import com.token2.lkcompanion.fidoui.AuthnkeyIntegration
import com.token2.lkcompanion.fidoui.FidoRepository
import com.token2.lkcompanion.fidoui.PasskeyAdapter
import com.token2.lkcompanion.oath.FeitianOtpApplet
import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.openpgp.OpenPgpApplet
import com.token2.lkcompanion.piv.PivApplet
import com.token2.lkcompanion.token2.Token2HidTransport
import com.token2.lkcompanion.token2ui.AddEntryDialog
import com.token2.lkcompanion.token2ui.Token2EntryAdapter
import com.token2.lkcompanion.oathui.OathEntryAdapter
import com.token2.lkcompanion.token2ui.Token2Repository
import com.token2.lkcompanion.token2ui.Token2PinRepository.OpResult as PinResult
import com.token2.lkcompanion.transport.NfcTransport
import com.token2.lkcompanion.transport.AppletUnavailableException
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException
import com.token2.lkcompanion.transport.UsbCcidTransport

/**
 * Single entry point. Owns both transports:
 *  - NFC via reader-mode callback (preferred over foreground dispatch for
 *    IsoDep: it disables Android's own NDEF handling so we get a clean APDU pipe)
 *  - USB via USB_DEVICE_ATTACHED + runtime permission, then CCID endpoint probe
 *
 * Once a transport is up, it runs a non-destructive "identify" pass: SELECT each
 * applet and read status. Destructive actions live behind explicit buttons in
 * the per-applet fragments (not wired here to keep the skeleton honest).
 */
class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var usbManager: UsbManager
    private lateinit var statusView: TextView
    private lateinit var armedHint: TextView
    private lateinit var otpList: RecyclerView
    private lateinit var adapter: Token2EntryAdapter
    private val repo = Token2Repository()
    private lateinit var oathAdapter: com.token2.lkcompanion.oathui.OathEntryAdapter
    private val oathRepo = com.token2.lkcompanion.oathui.OathRepository()

    // YubiKey Management applet (enable/disable applications). Runs on the next
    // tap regardless of tab; `managementPending` gates that one-shot dispatch.
    private val managementRepo = com.token2.lkcompanion.management.ManagementRepository()
    @Volatile private var managementPending = false

    // OTP PIN (privacy protection). Runs over CCID/NFC on the next tap;
    // pinPending gates the one-shot dispatch.
    private val pinRepo = com.token2.lkcompanion.token2ui.Token2PinRepository()
    @Volatile private var pinPending = false
    /** Whether the current OTP backend uses the shared smart-card OTP UI. */
    private var otpIsOath = false

    // FIDO2 tab
    private enum class Mode { INFO, TOTP, FIDO }
    private var mode = Mode.INFO
    private lateinit var paneInfo: View
    private lateinit var paneTotp: View
    private lateinit var paneFido: View
    private lateinit var infoCard: android.widget.LinearLayout
    private lateinit var infoStatusCard: StatusCard
    private lateinit var infoHint: TextView
    private lateinit var fidoStatus: TextView
    private lateinit var fidoCard: android.widget.LinearLayout
    private lateinit var statusCard: android.widget.LinearLayout
    private lateinit var otpStatusCard: StatusCard
    private lateinit var fidoStatusCard: StatusCard
    private lateinit var fidoArmedHint: TextView
    private lateinit var passkeyList: RecyclerView
    private lateinit var passkeyAdapter: PasskeyAdapter
    private lateinit var panePasskeys: View
    private lateinit var passkeyHint: TextView
    private var passkeyScreenOpen = false
    private lateinit var paneFingerprints: View
    private lateinit var fpHint: TextView
    private lateinit var fpList: RecyclerView
    private lateinit var fpAdapter: com.token2.lkcompanion.fidoui.FingerprintAdapter
    private var fpScreenOpen = false
    private val fidoRepo = FidoRepository()
    private val mds by lazy { com.token2.lkcompanion.fido.MdsRepository(applicationContext).also { it.load() } }
    @Volatile private var cachedPivStatus: com.token2.lkcompanion.piv.PivApplet.PivStatus? = null
    @Volatile private var cachedPgpStatus: com.token2.lkcompanion.openpgp.OpenPgpApplet.CardStatus? = null
    /** A USB key that has permission and is currently connected (for tab-switch re-reads). */
    private var connectedUsbDevice: UsbDevice? = null
    /** Identity of the current key connection ("usb:<devname>" / "nfc:<uid>"); FIDO
     *  caches are dropped whenever it changes, so one key's data is never shown for another. */
    @Volatile private var keySessionKey: String? = null
    /** Serializes all USB reads so two taps/resumes can't race on one connection. */
    private val usbExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
    /** Guard so a replug (attach intent + resume) doesn't open the same device twice. */
    @Volatile private var usbBusy = false
    private var otpOperationDialog: androidx.appcompat.app.AlertDialog? = null

    // NFC tap overlay
    private lateinit var nfcOverlay: View
    private lateinit var nfcOverlayTitle: TextView
    private lateinit var nfcOverlaySubtitle: TextView
    private lateinit var nfcPulseCircle: View

    /** Live add-dialog handle awaiting a scan result. */
    private var pendingScanHandle: AddEntryDialog.Handle? = null

    /** ZXing scan launcher — registered at construction (required by the API). */
    private val qrLauncher = registerForActivityResult(
        com.journeyapps.barcodescanner.ScanContract()
    ) { result ->
        val contents = result?.contents
        if (contents != null) {
            pendingScanHandle?.applyScannedUri(contents)
        }
        pendingScanHandle = null
    }

    private val usbPermissionAction = "com.token2.lkcompanion.USB_PERMISSION"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applySystemBarInsets()
        statusView = findViewById(R.id.statusText)
        armedHint = findViewById(R.id.armedHint)
        fidoStatus = findViewById(R.id.fidoStatus)
        fidoArmedHint = findViewById(R.id.fidoArmedHint)
        fidoCard = findViewById(R.id.fidoCard)
        statusCard = findViewById(R.id.statusCard)
        infoCard = findViewById(R.id.infoCard)
        infoHint = findViewById(R.id.infoHint)
        otpStatusCard = StatusCard(statusCard)
        fidoStatusCard = StatusCard(fidoCard)
        infoStatusCard = StatusCard(infoCard)
        infoStatusCard.renderHint("Tap your key to the phone to see what it supports.")
        fidoStatusCard.renderHint("Tap your key to read FIDO2 status.")
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        usbManager = getSystemService(Context.USB_SERVICE) as UsbManager

        // NFC tap overlay
        nfcOverlay = findViewById(R.id.nfcOverlay)
        nfcOverlayTitle = findViewById(R.id.nfcOverlayTitle)
        nfcOverlaySubtitle = findViewById(R.id.nfcOverlaySubtitle)
        nfcPulseCircle = findViewById(R.id.nfcPulseCircle)
        findViewById<android.widget.Button>(R.id.nfcOverlayCancel).setOnClickListener {
            cancelPendingOtpOperation()
            hideNfcOverlay()
        }

        // Token2 OTP list
        otpList = findViewById(R.id.otpList)
        otpList.layoutManager = LinearLayoutManager(this)
        adapter = Token2EntryAdapter(
            onDelete = { entry -> confirmDelete(entry) },
            onCopy = { entry ->
                entry.otpCode?.let { code ->
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE)
                        as android.content.ClipboardManager
                    clipboard.setPrimaryClip(
                        android.content.ClipData.newPlainText("OTP code", code))
                    android.widget.Toast.makeText(
                        this, "Code copied", android.widget.Toast.LENGTH_SHORT).show()
                }
            },
        )
        otpList.adapter = adapter

        // OATH adapter (for keys using the standard OATH applet, e.g. Pico/YubiKey).
        oathAdapter = OathEntryAdapter(
            onDelete = { d -> confirmDeleteOath(d) },
            onCopy = { d ->
                d.code?.let { code ->
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE)
                        as android.content.ClipboardManager
                    clipboard.setPrimaryClip(
                        android.content.ClipData.newPlainText("OTP code", code))
                    android.widget.Toast.makeText(
                        this, "Code copied", android.widget.Toast.LENGTH_SHORT).show()
                }
            },
            onCalculate = { d -> calculateOath(d) },
        )
        findViewById<android.widget.ImageButton>(R.id.btnRefresh).setOnClickListener {
            if (!armOtpRefresh()) {
                toast("Finish or cancel the current OTP operation before refreshing.")
                return@setOnClickListener
            }
            showNfcOverlay("Hold your key to the phone", "Reading OTP entries…")
        }
        findViewById<android.widget.ImageButton>(R.id.btnOtpLock).setOnClickListener {
            if (otpUnlocked) {
                // Lock: forget PIN + close device window on next contact.
                rememberedOtpPin = null
                repo.lockNow()
                otpUnlocked = false
                adapter.submit(emptyList())
                armedHint.text = "🔒 OTP codes locked — tap the lock to unlock."
                updateOtpLockButton()
                repo.arm(Token2Repository.PendingOp.Refresh)
                if (connectedUsbDevice != null) rereadUsbForCurrentTab()
                toast("OTP codes locked.")
            } else {
                // Unlock: prompt for the PIN (or use remembered), then read.
                promptUnlockPin()
            }
        }
        findViewById<android.widget.ImageButton>(R.id.btnAdd).setOnClickListener {
            // Freeze the destination while the dialog is open. A QR scan may leave
            // the activity briefly, during which a different key can be connected.
            val oathTarget = oathRepo.activeBackend.takeIf { otpIsOath }
            val targetsOath = otpIsOath
            AddEntryDialog.show(
                context = this,
                onScanRequested = { handle ->
                    pendingScanHandle = handle
                    val opts = com.journeyapps.barcodescanner.ScanOptions().apply {
                        setDesiredBarcodeFormats(
                            com.journeyapps.barcodescanner.ScanOptions.QR_CODE)
                        setPrompt("Scan an OTP QR code")
                        setBeepEnabled(false)
                        setOrientationLocked(true)   // follow the app's portrait UI
                    }
                    qrLauncher.launch(opts)
                },
                onReady = onReady@{ entry ->
                    if (targetsOath) {
                        val backend = oathTarget ?: run {
                            toast("Read the OTP key again before adding a credential.")
                            return@onReady false
                        }
                        // Convert the parsed entry to an OATH credential and arm OATH add.
                        val cred = entryToOathCredential(entry, backend)
                        return@onReady startOathOperation(
                            com.token2.lkcompanion.oathui.OathRepository.PendingOp.Add(
                                cred,
                                expectedBackend = backend,
                            ),
                            "add ${entry.accountName}",
                        ) {
                            showNfcOverlay("Hold your key to the phone", "Writing ${entry.accountName}…")
                        }
                    }
                    val cachedDup = repo.cachedDuplicateOf(entry)
                    if (cachedDup != null) {
                        // Advisory: cache suggests this identity already exists.
                        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                            .setTitle("Possible duplicate")
                            .setMessage("\"${cachedDup.appName} / ${cachedDup.accountName}\" " +
                                "looks like it's already on the key. Overwrite it when you tap?")
                            .setPositiveButton("Overwrite") { _, _ ->
                                repo.arm(Token2Repository.PendingOp.Add(entry, allowOverwrite = true))
                                showNfcOverlay("Hold your key to the phone",
                                    "Replacing ${entry.accountName}…")
                            }
                            .setNegativeButton("Cancel", null)
                            .show()
                        true
                    } else {
                        repo.arm(Token2Repository.PendingOp.Add(entry))
                        showNfcOverlay("Hold your key to the phone",
                            "Writing ${entry.accountName}…")
                        true
                    }
                },
                importPolicy = if (oathTarget ==
                    com.token2.lkcompanion.oathui.OathRepository.BackendKind.FEITIAN) {
                    AddEntryDialog.ImportPolicy.FEITIAN
                } else {
                    AddEntryDialog.ImportPolicy.LEGACY_TOTP
                },
                allowedDigits = oathTarget?.allowedImportDigits,
            )
        }

        // ===== FIDO2 tab + passkey screen =====
        panePasskeys = findViewById(R.id.panePasskeys)
        passkeyHint = findViewById(R.id.passkeyHint)
        passkeyList = findViewById(R.id.passkeyList)
        passkeyList.layoutManager = LinearLayoutManager(this)
        passkeyAdapter = PasskeyAdapter(
            onDelete = { pk -> confirmDeletePasskey(pk) },
            onInfo = { pk -> showPasskeyInfo(pk) },
        )
        passkeyList.adapter = passkeyAdapter
        findViewById<android.widget.ImageButton>(R.id.btnPasskeyBack).setOnClickListener {
            closePasskeyScreen()
        }

        // Fingerprints screen
        paneFingerprints = findViewById(R.id.paneFingerprints)
        fpHint = findViewById(R.id.fpHint)
        fpList = findViewById(R.id.fpList)
        fpList.layoutManager = LinearLayoutManager(this)
        fpAdapter = com.token2.lkcompanion.fidoui.FingerprintAdapter(
            onRemove = { fp -> confirmRemoveFingerprint(fp) },
            onRename = { fp -> promptRenameFingerprint(fp) },
        )
        fpList.adapter = fpAdapter
        findViewById<android.widget.ImageButton>(R.id.btnFpBack).setOnClickListener {
            closeFingerprintScreen()
        }
        findViewById<android.widget.ImageButton>(R.id.btnFpAdd).setOnClickListener {
            startFingerprintEnroll()
        }
        // Tapping the empty FIDO card (before first read) triggers a read.
        fidoCard.setOnClickListener {
            if (fidoRepo.lastInfo == null) {
                fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
                showNfcOverlay("Hold your key to the phone", "Reading FIDO2 status…")
            }
        }

        // ===== bottom navigation: switch panes =====
        paneInfo = findViewById(R.id.paneInfo)
        paneTotp = findViewById(R.id.paneTotp)
        paneFido = findViewById(R.id.paneFido)
        val bottomNav = findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(
            R.id.bottomNav)
        bottomNav.setOnItemSelectedListener { item ->
            val newMode = when (item.itemId) {
                R.id.nav_info -> Mode.INFO
                R.id.nav_totp -> Mode.TOTP
                R.id.nav_fido -> Mode.FIDO
                else -> return@setOnItemSelectedListener false
            }
            mode = newMode
            showPane(newMode)
            // Over USB the key stays plugged in, so there's no re-tap to trigger a
            // read. Re-read the live device for the newly-selected tab.
            if (mode == Mode.TOTP) {
                if (armOtpRefresh()) rereadUsbForCurrentTab()
            } else {
                if (mode == Mode.FIDO) fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
                rereadUsbForCurrentTab()
            }
            true
        }
        showPane(Mode.INFO)   // start on Info

        // toolbar
        setSupportActionBar(findViewById(R.id.toolbar))
        // We provide our own logo + title views inside the toolbar, so suppress the
        // default title and logo.
        supportActionBar?.setDisplayShowTitleEnabled(false)
        // Build version next to the title — lets you confirm which build is running.
        findViewById<TextView>(R.id.toolbarSubtitle).text = try {
            "v" + packageManager.getPackageInfo(packageName, 0).versionName
        } catch (_: Exception) { "" }
        // Long-press the toolbar to open USB diagnostics, independent of the overflow
        // menu (in case a stale menu resource hides the menu item).
        findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar).setOnLongClickListener {
            showUsbDiagnostics(); true
        }

        startTotpTicker()
        registerReceiver(usbReceiver, IntentFilter(usbPermissionAction),
            RECEIVER_NOT_EXPORTED)
        registerReceiver(usbDetachReceiver,
            IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED), RECEIVER_NOT_EXPORTED)
        // Runtime receiver for hot-plug: pick up a key plugged in while the app is
        // already open. This is NOT a manifest intent-filter, so it does not bring
        // back the global "open this app?" launch prompt from issue #1 — that prompt
        // only comes from a manifest-declared USB_DEVICE_ATTACHED filter.
        registerReceiver(usbAttachReceiver,
            IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED), RECEIVER_NOT_EXPORTED)
    }

    /**
     * Edge-to-edge inset handling. targetSdk 35 (Android 15) forces the window to
     * draw under the system bars, so without this the pink toolbar would render
     * behind the status bar (issue #2). We keep the bars' colored backgrounds
     * extending edge-to-edge but pad each top bar down by the status-bar inset and
     * the bottom navigation up by the navigation-bar inset, so no content collides
     * with the system bars. Applied as a listener so it survives rotation, split
     * screen, and gesture/3-button nav changes.
     */
    private fun applySystemBarInsets() {
        // Draw edge-to-edge on all versions (mandatory on API 35) and keep the
        // status-bar icons light, since our status bar sits over the dark-pink bar.
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val controller = WindowCompat.getInsetsController(window, window.decorView)
        controller.isAppearanceLightStatusBars = false
        controller.isAppearanceLightNavigationBars = !isNightMode()
        val root = findViewById<View>(android.R.id.content)
        // Top bars that must clear the status bar (main toolbar + overlay headers).
        val topBarIds = intArrayOf(R.id.toolbar, R.id.passkeyHeaderBar, R.id.fpHeaderBar)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        // Full-screen overlays have no bottom nav, so their lists must clear the
        // navigation bar themselves.
        val bottomListIds = intArrayOf(R.id.passkeyList, R.id.fpList)
        // Cache each top bar's original top padding so repeated insets don't stack.
        val baseTopPadding = topBarIds.associateWith { id ->
            findViewById<View>(id)?.paddingTop ?: 0
        }
        val baseNavBottomPadding = bottomNav?.paddingBottom ?: 0
        val baseListBottomPadding = bottomListIds.associateWith { id ->
            findViewById<View>(id)?.paddingBottom ?: 0
        }

        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            for (id in topBarIds) {
                findViewById<View>(id)?.updatePadding(top = (baseTopPadding[id] ?: 0) + bars.top)
            }
            bottomNav?.updatePadding(bottom = baseNavBottomPadding + bars.bottom)
            for (id in bottomListIds) {
                findViewById<View>(id)?.updatePadding(
                    bottom = (baseListBottomPadding[id] ?: 0) + bars.bottom)
            }
            insets
        }
    }

    private fun isNightMode(): Boolean =
        (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES

    /** Request a refresh without overwriting a pending/retryable OATH operation. */
    private fun armOtpRefresh(): Boolean {
        if (!otpIsOath) {
            repo.arm(Token2Repository.PendingOp.Refresh)
            return true
        }
        if (!oathRepo.requestRefresh()) return false
        repo.arm(Token2Repository.PendingOp.Refresh)
        return true
    }

    /** Explicit cancellation is separate from refresh so an in-flight APDU stays intact. */
    private fun cancelPendingOtpOperation() {
        if (otpIsOath) {
            oathRepo.cancelPending()
        } else {
            repo.arm(Token2Repository.PendingOp.Refresh)
        }
    }

    /** 1s ticker drives the TOTP countdown on already-fetched codes. */
    private fun startTotpTicker() {
        val handler = android.os.Handler(mainLooper)
        val r = object : Runnable {
            override fun run() {
                val now = System.currentTimeMillis() / 1000
                if (otpIsOath) {
                    oathAdapter.tick(now)
                } else {
                    adapter.tick(
                        com.token2.lkcompanion.oath.OathCore.secondsRemaining(now, 30)
                    )
                }
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(r)
    }

    override fun onResume() {
        super.onResume()
        // Reader mode: skip NDEF check + presence sound; gives us raw IsoDep.
        nfcAdapter?.enableReaderMode(
            this, this,
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null)
        // Also pick up a key that was already plugged in before the app opened —
        // the USB_DEVICE_ATTACHED intent only fires on a fresh attach.
        scanConnectedUsb()
    }

    /** Look through currently-attached USB devices for a smart-card/security key. */
    private fun scanConnectedUsb() {
        // Already tracking a connected key? Don't re-open it on every resume.
        if (connectedUsbDevice != null) return
        // Just detached something — don't immediately re-prompt for permission.
        if (System.currentTimeMillis() < suppressScanUntil) return
        val devices = usbManager.deviceList.values
        if (devices.isEmpty()) return
        for (device in devices) {
            if (looksLikeKey(device)) {
                // This only runs from onResume(), i.e. while the app is in the
                // foreground, so it's fine to request the one-time USB consent here.
                // (We no longer register a USB_DEVICE_ATTACHED intent-filter, which
                // used to make Android offer to launch the app on every device plug
                // even while closed — issue #1. Consent now only happens with the
                // app open and foregrounded.)
                if (usbManager.hasPermission(device)) openUsb(device)
                else requestUsbPermission(device)
                return
            }
        }
    }

    /** Heuristic: a CCID interface, or a Token2 vendor ID. */
    private fun looksLikeKey(device: UsbDevice): Boolean {
        if (device.vendorId == Token2HidTransport.VENDOR_ID) return true
        for (i in 0 until device.interfaceCount) {
            val cls = device.getInterface(i).interfaceClass
            if (cls == UsbCcidTransport.USB_CLASS_CCID ||
                cls == android.hardware.usb.UsbConstants.USB_CLASS_HID) return true
        }
        return false
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    // --- NFC ---
    override fun onTagDiscovered(tag: Tag) {
        val sessionKey = "nfc:" + (tag.id ?: ByteArray(0)).joinToString("") { "%02x".format(it) }
        if (sessionKey != keySessionKey) {
            keySessionKey = sessionKey
            fidoRepo.clearCaches()   // includes the remembered PIN
            fpPinOwnedByScreen = false
            // Token2 OTP PIN gets no pass across keys either.
            rememberedOtpPin = null
            repo.clearPin()
        }
        val isoDep = IsoDep.get(tag) ?: run {
            post("Tag is not ISO-DEP (not a smart-card key)."); return
        }
        runWithTransport(NfcTransport(isoDep))
    }

    // --- USB ---
    private fun requestUsbPermission(device: UsbDevice) {
        if (usbManager.hasPermission(device)) { openUsb(device); return }
        val pi = PendingIntent.getBroadcast(
            this, 0, Intent(usbPermissionAction).setPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE)
        usbManager.requestPermission(device, pi)
    }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != usbPermissionAction) return
            val device = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE) ?: return
            if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) openUsb(device)
            else post("USB permission denied.")
        }
    }

    private val usbDetachReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != UsbManager.ACTION_USB_DEVICE_DETACHED) return
            val detached = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
            // Only react if it's the key we were tracking (composite devices can emit
            // detach for sibling interfaces we don't care about).
            if (detached != null && connectedUsbDevice != null &&
                detached.deviceName != connectedUsbDevice!!.deviceName) return
            connectedUsbDevice = null
            usbBusy = false
            // Briefly suppress auto-scan so we don't immediately re-pop the permission
            // dialog for a device that's mid-unplug (or a re-enumerating composite key).
            suppressScanUntil = System.currentTimeMillis() + 1500
            clearKeyData("Key unplugged.")
        }
    }

    private val usbAttachReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != UsbManager.ACTION_USB_DEVICE_ATTACHED) return
            val device = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE) ?: return
            if (connectedUsbDevice != null) return        // already handling a key
            if (!looksLikeKey(device)) return
            // Fresh user-initiated plug: don't let a recent detach suppress it.
            suppressScanUntil = 0L
            if (usbManager.hasPermission(device)) openUsb(device)
            else requestUsbPermission(device)
        }
    }

    /** Set briefly after a detach to debounce the resume-scan permission prompt. */
    @Volatile private var suppressScanUntil = 0L

    /**
     * Wipe all on-screen data that belongs to a now-absent key, so stale values
     * (OTP codes, FIDO status, passkeys) don't linger. Called on USB detach.
     */
    private fun clearKeyData(reason: String) {
        // Clear cached state in the repositories too, so a later read starts fresh.
        repo.arm(Token2Repository.PendingOp.Refresh)
        oathRepo.onTransportDisconnected()
        fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
        fidoRepo.clearCaches()
        fpPinOwnedByScreen = false
        // The Token2 OTP PIN must not carry across keys either — a wrong one
        // burns retry counters whose exhaustion wipes all OTP profiles.
        rememberedOtpPin = null
        repo.clearPin()
        oathRepo.forgetPasswords()
        runOnUiThread {
            otpOperationDialog?.dismiss()
            otpOperationDialog = null
            otpIsOath = false
            if (otpList.adapter !== adapter) otpList.adapter = adapter
            adapter.submit(emptyList())
            oathAdapter.submit(emptyList())
            passkeyAdapter.submit(emptyList())
            infoStatusCard.renderHint("Tap your key to the phone to see what it supports.")
            fidoStatusCard.renderHint("Tap your key to read FIDO2 status.")
            otpStatusCard.renderHint(getString(R.string.tap_prompt))
            armedHint.text = reason
            fidoArmedHint.text = reason
            if (passkeyScreenOpen) passkeyHint.text = reason
            hideNfcOverlay()
        }
    }

    /**
     * Open the USB key and run the current tab's read, serialized on a single
     * thread. A replug fires both the attach intent and onResume, so [usbBusy]
     * guards against opening the same device twice concurrently.
     */
    private fun openUsb(device: UsbDevice) {
        val sessionKey = "usb:" + device.deviceName
        if (sessionKey != keySessionKey) {
            // A different connection than last time (replug, key swap, hub switch):
            // stale FIDO data AND any remembered PIN (FIDO or Token2 OTP) must
            // never survive into the new key's session.
            keySessionKey = sessionKey
            fidoRepo.clearCaches()   // includes the remembered PIN
            fpPinOwnedByScreen = false
            rememberedOtpPin = null
            repo.clearPin()
        }
        connectedUsbDevice = device
        if (usbBusy) return            // a read is already in flight; don't double-open
        usbBusy = true
        usbExecutor.execute {
            try {
                openUsbBlocking(device)
            } catch (e: Exception) {
                runOnUiThread { post("USB error: ${e.message ?: e.javaClass.simpleName}") }
            } finally {
                usbBusy = false
                runOnUiThread { hideNfcOverlay() }
            }
        }
    }

    /** Runs on the usbExecutor thread. Picks the interface by current mode. */
    private fun openUsbBlocking(device: UsbDevice) {
        // FIDO2 over USB is HID-only (CCID rejects the FIDO applet, SW 6A81).
        if (mode == Mode.FIDO) { fidoOverHidBlocking(device); return }

        // INFO and TOTP use the CCID smart-card interface.
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            val eps = UsbCcidTransport.findCcidEndpoints(iface) ?: continue
            val conn = usbManager.openDevice(device)
                ?: throw IllegalStateException("openDevice returned null")
            val transport = UsbCcidTransport(conn, iface, eps.first, eps.second)
            try {
                if (managementPending) {
                    managementPending = false
                    runManagementTap(transport)
                } else if (pinPending) {
                    pinPending = false
                    runPinTap(transport)
                } else if (mode == Mode.INFO) readInfoOverlay(transport, device)
                else readToken2(transport)
            } finally {
                transport.close()
            }
            return
        }
        // No CCID interface — Token2 OTP may be on the HID channel.
        if (device.vendorId == Token2HidTransport.VENDOR_ID && mode != Mode.FIDO) {
            for (i in 0 until device.interfaceCount) {
                val iface = device.getInterface(i)
                if (iface.interfaceClass == android.hardware.usb.UsbConstants.USB_CLASS_HID) {
                    runToken2Hid(device, iface); return
                }
            }
        }
        // No CCID at all. FIDO-only keys (e.g. YubiKey Security Key series) have just
        // a CTAPHID interface. On the Info tab, detect FIDO and show it as available
        // rather than a dead-end; the FIDO tab handles it directly. We also read the
        // AAGUID here so the Info card can show the MDS name/cert/icon over USB.
        val conn = usbManager.openDevice(device)
        val wire = if (conn != null)
            com.token2.lkcompanion.fido.ctap.CtapHidWire.find(conn, device) else null
        val hasFido = wire != null
        var fidoInfo: com.token2.lkcompanion.fido.ctap.Ctap2Client.Info? = null
        if (wire != null) {
            fidoInfo = try { com.token2.lkcompanion.fido.ctap.Ctap2Client(wire).getInfo() }
                catch (_: Exception) { null }
        }
        conn?.close()
        if (hasFido) {
            if (mode == Mode.INFO) showFidoOnlyInfo(fidoInfo)
            else runOnUiThread { post("This key is FIDO2-only — use the FIDO2 tab.") }
            return
        }
        runOnUiThread { post("No usable interface on this USB device.") }
    }

    /** Info overview for a FIDO2-only key (no CCID): one card pointing to the FIDO tab.
     *  If we could read the AAGUID, enrich the FIDO row with MDS name/cert/icon. */
    private fun showFidoOnlyInfo(info: com.token2.lkcompanion.fido.ctap.Ctap2Client.Info? = null) {
        runOnUiThread {
            val rows = ArrayList<StatusCard.Row>()
            rows.add(StatusCard.Row(
                iconRes = R.drawable.ic_contactless, label = "Connected",
                secondary = "USB · FIDO2-only key",
                chipText = "OK", chipState = StatusCard.State.SUCCESS))
            val mdsEntry = mds.lookup(info?.aaguidHex)
            val mdsIcon = com.token2.lkcompanion.fido.MdsRepository.decodeIcon(mdsEntry?.iconDataUri)
            rows.add(StatusCard.Row(
                iconRes = R.drawable.ic_key,
                iconBitmap = mdsIcon,
                label = mdsEntry?.name ?: "FIDO2",
                secondary = if (mdsEntry != null)
                    certLabel(mdsEntry.certification) + " · open the FIDO2 tab to manage"
                else "open the FIDO2 tab to manage",
                chipText = "Present", chipState = StatusCard.State.SUCCESS,
                onClick = { goToTab(Mode.FIDO, R.id.nav_fido) }))
            hideNfcOverlay(); infoStatusCard.render(rows)
        }
    }

    /** Blocking Token2 OTP over the USB-HID channel (no CCID interface present). */
    private fun runToken2Hid(device: UsbDevice, hidIface: UsbInterface) {
        try {
            val conn = usbManager.openDevice(device)
                ?: throw TransportException("openDevice returned null")
            val hid = Token2HidTransport(conn, hidIface)
            val client = com.token2.lkcompanion.token2.Token2Client.overHid(hid)
            val entries = try {
                client.enumerate(System.currentTimeMillis() / 1000)
            } catch (e: com.token2.lkcompanion.token2.Token2Exception.EntryNotFound) {
                emptyList()
            }
            runOnUiThread {
                otpIsOath = false
                if (otpList.adapter !== adapter) otpList.adapter = adapter
                adapter.submit(entries)
                armedHint.text = "Token2 OTP over USB-HID: ${entries.size} entr" +
                    (if (entries.size == 1) "y" else "ies")
            }
            hid.close()
        } catch (e: Exception) {
            runOnUiThread { armedHint.text = "Token2 USB-HID failed: ${e.message}" }
        }
    }

    // --- on tap: route to the active tab's operation ---
    private fun runWithTransport(transport: SmartCardTransport) {
        // A pending Management-applet op (enable/disable apps) runs on the next
        // tap regardless of which tab is showing, then clears.
        if (managementPending) {
            managementPending = false
            Thread { try { runManagementTap(transport) } finally { transport.close() } }.start()
            return
        }
        if (pinPending) {
            pinPending = false
            Thread { try { runPinTap(transport) } finally { transport.close() } }.start()
            return
        }
        when (mode) {
            Mode.FIDO -> { runFidoTap(transport); return }
            Mode.INFO -> { Thread { try { readInfoOverlay(transport) } finally { transport.close() } }.start(); return }
            Mode.TOTP -> Thread { try { readToken2(transport) } finally { transport.close() } }.start()
        }
    }

    /** Blocking Token2 OTP read + UI update. Caller owns transport lifecycle. */
    private fun readToken2(transport: SmartCardTransport) {
        // A queued OATH/Feitian mutation has a fixed owner. Do not probe Token2
        // first, because a valid Token2 key must never hide or consume that state.
        if (oathRepo.hasPendingOperation()) {
            readOath(transport)
            return
        }
        val result = repo.executeOn(transport)
        // If this isn't a Token2 key, try the standard OATH applet (Pico/YubiKey).
        if (result is Token2Repository.OpResult.NotAToken2Key) {
            if (repo.pending !is Token2Repository.PendingOp.Refresh) {
                // A Token2 mutation was armed for a different physical key. Cancel
                // it explicitly instead of carrying it into a later Token2 tap.
                repo.arm(Token2Repository.PendingOp.Refresh)
                otpIsOath = false
                runOnUiThread {
                    if (otpList.adapter !== adapter) otpList.adapter = adapter
                    hideNfcOverlay()
                    armedHint.text =
                        "Token2 operation cancelled: the presented key is not a Token2 OTP key."
                }
                return
            }
            readOath(transport)
            return
        }
        // The current key is Token2; discard capabilities cached from an older
        // OATH/Feitian key before another Add dialog is opened.
        oathRepo.clearCache()
        otpIsOath = false
        runOnUiThread {
            if (otpList.adapter !== adapter) otpList.adapter = adapter
            hideNfcOverlay()
            when (result) {
                is Token2Repository.OpResult.Success -> {
                    adapter.submit(result.entries)
                    if (repo.hasPin()) {
                        otpProtected = true; otpUnlocked = true
                    } else {
                        // A clean read with no PIN in play — this key isn't
                        // protected (or we're not tracking one); hide the lock.
                        otpProtected = false; otpUnlocked = false
                    }
                    updateOtpLockButton()
                    armedHint.text = "${result.message}. ${result.entries.size} entr" +
                        if (result.entries.size == 1) "y." else "ies."
                }
                is Token2Repository.OpResult.DuplicateExists -> {
                    adapter.submit(result.entries)
                    com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                        .setTitle("Entry already exists")
                        .setMessage("\"${result.existingLabel}\" is already on the key. Overwrite it?")
                        .setPositiveButton("Overwrite") { _, _ ->
                            repo.arm(Token2Repository.PendingOp.Add(result.entry, allowOverwrite = true))
                            showNfcOverlay("Hold your key to the phone", "Replacing ${result.entry.accountName}…")
                        }
                        .setNegativeButton("Cancel") { _, _ ->
                            repo.arm(Token2Repository.PendingOp.Refresh)
                            armedHint.text = "Add cancelled — entry already exists."
                        }
                        .show()
                }
                is Token2Repository.OpResult.Failure ->
                    armedHint.text = "Failed: ${result.message}"
                is Token2Repository.OpResult.Config -> {
                    adapter.submit(repo.cachedEntries)
                    showInterfaceDialog(result.iface)
                }
                Token2Repository.OpResult.PinRequired -> {
                    otpProtected = true; otpUnlocked = false; updateOtpLockButton()
                    armedHint.text = "🔒 Codes are PIN-protected — tap the lock to unlock."
                    adapter.submit(emptyList())   // don't leave stale/foreign entries
                    promptUnlockPin()
                }
                is Token2Repository.OpResult.PinWrong -> {
                    otpProtected = true; otpUnlocked = false; updateOtpLockButton()
                    if (rememberedOtpPin != null) {
                        rememberedOtpPin = null
                    }
                    val left = result.retriesLeft
                    val max = result.maxRetries
                    val detail = if (left != null && max != null) " — $left of $max attempts left"
                        else if (left != null) " — $left attempts left" else ""
                    toast("Wrong OTP PIN$detail")
                    promptUnlockPin()
                }
                Token2Repository.OpResult.NotAToken2Key -> { /* handled above */ }
            }
        }
    }

    /**
     * Enable/disable the key's USB interfaces (FIDO / keyboard-HID / CCID),
     * §6.8. Presented with the current state pre-filled; enforces the
     * two-interface minimum both here (Apply disabled) and in the client.
     */
    private fun showInterfaceDialog(state: Token2Repository.IfaceState) {
        // Custom view: a framework CheckBox (always renders; no null-text
        // measurement bug like MaterialSwitch, and unlike setMultiChoiceItems it
        // can coexist with explanatory text). FIDO and CCID are always left
        // enabled, so toggling this can never brick the key.
        val ctx = this
        val pad = (20 * resources.displayMetrics.density).toInt()
        val container = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
        }
        val info = android.widget.TextView(ctx).apply {
            text = "Enable or disable the key's keyboard-HID interface, which types " +
                "HOTP codes on a button touch. FIDO2 and the smart-card interface " +
                "are left untouched. Re-plug the key for the change to take effect."
            textSize = 14f
            setPadding(0, 0, 0, pad)
        }
        val cb = android.widget.CheckBox(ctx).apply {
            text = "Keyboard-HID enabled (HOTP-on-touch)"
            isChecked = state.keyboard
        }
        container.addView(info)
        container.addView(cb)

        com.google.android.material.dialog.MaterialAlertDialogBuilder(ctx)
            .setTitle("HID-HOTP interface")
            .setView(container)
            .setPositiveButton("Apply") { _, _ ->
                val kbd = cb.isChecked
                if (kbd == state.keyboard) armedHint.text = "No change to apply."
                else confirmInterfaceChange(state, kbd)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Final confirmation before toggling keyboard-HID, then arm + tap. */
    private fun confirmInterfaceChange(
        before: Token2Repository.IfaceState,
        keyboard: Boolean,
    ) {
        val verb = if (keyboard) "enable" else "disable"
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Reconfigure interface?")
            .setMessage(
                "Keyboard-HID will be ${verb}d.\n\nThis reconfigures the hardware. " +
                    "Re-plug the key afterwards for the change to take effect."
            )
            .setPositiveButton("Reconfigure") { _, _ ->
                // FIDO and CCID stay enabled; only keyboard varies.
                repo.arm(Token2Repository.PendingOp.SetInterfaces(
                    fido = true, keyboard = keyboard, ccid = true))
                // USB-only: drive the write over the already-plugged key.
                if (connectedUsbDevice != null) rereadUsbForCurrentTab()
                else toast("Plug the Token2 key into USB to apply.")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ===== YubiKey Management applet: enable/disable applications =====

    /** Runs the armed Management op against a tapped/plugged YubiKey. */
    private fun runManagementTap(transport: SmartCardTransport) {
        val result = managementRepo.executeOn(transport)
        runOnUiThread {
            hideNfcOverlay()
            when (result) {
                is com.token2.lkcompanion.management.ManagementRepository.OpResult.Info ->
                    showApplicationsDialog(result.info)
                is com.token2.lkcompanion.management.ManagementRepository.OpResult.Success ->
                    toast(result.message)
                is com.token2.lkcompanion.management.ManagementRepository.OpResult.Locked -> {
                    // Offer to retry with a lock code.
                    com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                        .setTitle("Configuration locked")
                        .setMessage(result.message + "\n\nEnter the lock code to retry.")
                        .setPositiveButton("Enter code", null)
                        .setNegativeButton("Cancel", null)
                        .show()
                    // The user re-opens the dialog from the menu; the pending write
                    // that failed is cleared, so nothing is retried automatically.
                }
                is com.token2.lkcompanion.management.ManagementRepository.OpResult.Failure ->
                    toast("Failed: ${result.message}")
                com.token2.lkcompanion.management.ManagementRepository.OpResult.NoManagementApplet ->
                    toast("No management applet — not a YubiKey 5-series key?")
            }
        }
    }

    /**
     * Per-application enable/disable dialog for a YubiKey, over USB and (if the
     * key supports it) NFC. Only *supported* applications are shown; each has a
     * USB switch and, when available, an NFC switch. Guards against disabling the
     * transport currently in use and against leaving no applications on a
     * transport.
     */
    private fun showApplicationsDialog(
        info: com.token2.lkcompanion.management.YkManagementClient.DeviceInfo,
    ) {
        val mgmt = com.token2.lkcompanion.management.YkManagementClient
        val ctx = this
        val pad = (16 * resources.displayMetrics.density).toInt()

        val root = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(pad + pad, pad, pad + pad, 0)
        }

        // Header row: USB / NFC column labels.
        val header = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
        }
        header.addView(android.widget.TextView(ctx).apply {
            text = "Application"; layoutParams = android.widget.LinearLayout.LayoutParams(0,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 2f)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        header.addView(android.widget.TextView(ctx).apply {
            text = "USB"; layoutParams = android.widget.LinearLayout.LayoutParams(0,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            gravity = android.view.Gravity.CENTER
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        if (info.nfcAvailable) header.addView(android.widget.TextView(ctx).apply {
            text = "NFC"; layoutParams = android.widget.LinearLayout.LayoutParams(0,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            gravity = android.view.Gravity.CENTER
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        root.addView(header)

        // Which transport are we connected over right now? Disallow turning off
        // the last app on that transport (would drop the connection we're using).
        val onNfc = connectedUsbDevice == null    // no USB device => this tap is NFC

        data class Row(
            val app: com.token2.lkcompanion.management.YkManagementClient.Application,
            val usb: com.google.android.material.materialswitch.MaterialSwitch?,
            val nfc: com.google.android.material.materialswitch.MaterialSwitch?,
        )
        val rows = ArrayList<Row>()

        for (app in mgmt.APPLICATIONS) {
            val usbSupported = info.usbHas(app.bit)
            val nfcSupported = info.nfcAvailable && info.nfcHas(app.bit)
            if (!usbSupported && !nfcSupported) continue    // not on this key at all

            val line = android.widget.LinearLayout(ctx).apply {
                orientation = android.widget.LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, pad / 2, 0, pad / 2)
            }
            line.addView(android.widget.TextView(ctx).apply {
                text = "${app.name}\n${app.description}"
                textSize = 13f
                layoutParams = android.widget.LinearLayout.LayoutParams(0,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 2f)
            })
            val usbSw = if (usbSupported)
                com.google.android.material.materialswitch.MaterialSwitch(ctx).apply {
                    showText = false; textOn = ""; textOff = ""
                    isChecked = info.usbOn(app.bit)
                } else null
            line.addView(usbSw ?: android.widget.Space(ctx), android.widget.LinearLayout.LayoutParams(0,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).also {
                it.gravity = android.view.Gravity.CENTER })

            var nfcSw: com.google.android.material.materialswitch.MaterialSwitch? = null
            if (info.nfcAvailable) {
                nfcSw = if (nfcSupported)
                    com.google.android.material.materialswitch.MaterialSwitch(ctx).apply {
                        showText = false; textOn = ""; textOff = ""
                        isChecked = info.nfcOn(app.bit)
                    } else null
                line.addView(nfcSw ?: android.widget.Space(ctx), android.widget.LinearLayout.LayoutParams(0,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).also {
                    it.gravity = android.view.Gravity.CENTER })
            }
            root.addView(line)
            rows.add(Row(app, usbSw, nfcSw))
        }

        val warn = android.widget.TextView(ctx).apply {
            setPadding(0, pad, 0, 0); textSize = 12f
        }
        root.addView(warn)

        val scroll = android.widget.ScrollView(ctx).apply { addView(root) }

        val subtitle = buildString {
            append("YubiKey")
            info.serial?.let { append(" · S/N $it") }
            append(" · fw ${info.firmware}")
            if (info.configLocked) append(" · 🔒 locked")
        }

        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(ctx)
            .setTitle("Applications")
            .setMessage(
                subtitle + "\n\nEnable or disable each application per transport. " +
                    "Disabling all applications that use an interface turns that " +
                    "interface off. The key reboots to apply — you may need to " +
                    "remove and reinsert it."
            )
            .setView(scroll)
            .setPositiveButton("Apply", null)
            .setNegativeButton("Cancel", null)
            .create()

        fun usbMask(): Int {
            var m = 0
            for (r in rows) if (r.usb?.isChecked == true) m = m or r.app.bit
            return m
        }
        fun nfcMask(): Int {
            var m = 0
            for (r in rows) if (r.nfc?.isChecked == true) m = m or r.app.bit
            return m
        }
        fun validate(): String? {
            if (usbMask() == 0 && !onNfc)
                return "At least one USB application must stay enabled — you're connected over USB."
            if (info.nfcAvailable && nfcMask() == 0 && onNfc)
                return "At least one NFC application must stay enabled — you're connected over NFC."
            return null
        }
        fun refresh() {
            val err = validate()
            warn.text = err ?: "Ready to apply."
            warn.setTextColor(if (err != null) 0xFFB00020.toInt() else 0x99888888.toInt())
            dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE)?.isEnabled = err == null
        }
        val listener = android.widget.CompoundButton.OnCheckedChangeListener { _, _ -> refresh() }
        for (r in rows) { r.usb?.setOnCheckedChangeListener(listener); r.nfc?.setOnCheckedChangeListener(listener) }

        dialog.setOnShowListener {
            refresh()
            dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val newUsb = usbMask()
                val newNfc = if (info.nfcAvailable) nfcMask() else null
                val unchanged = newUsb == info.usbEnabled &&
                    (newNfc == null || newNfc == info.nfcEnabled)
                if (unchanged) { toast("No changes to apply."); dialog.dismiss(); return@setOnClickListener }
                dialog.dismiss()
                confirmApplicationChange(info, newUsb, newNfc)
            }
        }
        dialog.show()
    }

    /** Confirm, prompt for a lock code if the key is locked, then arm + tap. */
    private fun confirmApplicationChange(
        info: com.token2.lkcompanion.management.YkManagementClient.DeviceInfo,
        newUsb: Int, newNfc: Int?,
    ) {
        fun proceed(lockCode: ByteArray?) {
            managementRepo.arm(
                com.token2.lkcompanion.management.ManagementRepository.PendingOp.SetCapabilities(
                    usbEnabled = newUsb, nfcEnabled = newNfc, lockCode = lockCode
                )
            )
            managementPending = true
            showNfcOverlay("Hold your key to the phone", "Applying application changes…")
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Reconfigure applications?")
            .setMessage(
                "This changes which applications the key exposes and reboots it. " +
                    "Continue?"
            )
            .setPositiveButton("Reconfigure") { _, _ ->
                if (info.configLocked) promptLockCode { code -> proceed(code) }
                else proceed(null)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Prompt for the 16-byte config lock, entered as 32 hex characters. */
    private fun promptLockCode(onCode: (ByteArray) -> Unit) {
        val input = android.widget.EditText(this).apply {
            hint = "32 hex characters (16 bytes)"
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            filters = arrayOf(android.text.InputFilter.LengthFilter(32))
        }
        val pad = (16 * resources.displayMetrics.density).toInt()
        val wrap = android.widget.FrameLayout(this).apply {
            setPadding(pad + pad, pad, pad + pad, 0); addView(input)
        }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Configuration lock code")
            .setMessage("This key's configuration is locked. Enter its 16-byte lock code as hex.")
            .setView(wrap)
            .setPositiveButton("Unlock & apply") { _, _ ->
                val hex = input.text.toString().trim().replace(" ", "")
                val bytes = hexToBytesOrNull(hex)
                if (bytes == null || bytes.size != com.token2.lkcompanion.management.YkManagementClient.LOCK_LEN)
                    toast("Lock code must be exactly 32 hex characters.")
                else onCode(bytes)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun hexToBytesOrNull(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        return try {
            ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (e: Exception) { null }
    }

    // ===== OTP PIN (privacy protection) =====================================

    /** Runs the armed PIN op against a tapped/plugged key over CCID/NFC. */
    private fun runPinTap(transport: SmartCardTransport) {
        val result = try {
            val client = com.token2.lkcompanion.token2.Token2Client.overNfc(transport)
            pinRepo.executeOn(client)
        } catch (e: Exception) {
            com.token2.lkcompanion.token2ui.Token2PinRepository.OpResult.Failure(
                e.message ?: e.javaClass.simpleName)
        }
        runOnUiThread {
            hideNfcOverlay()
            when (result) {
                is PinResult.Status -> showPinStatusDialog(result.flag)
                is PinResult.Success -> toast(result.message)
                is PinResult.WrongPin -> toast(
                    "Wrong PIN" + (result.retriesLeft?.let { " — $it retries left" } ?: ""))
                PinResult.Blocked -> com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                    .setTitle("PIN locked out")
                    .setMessage("The OTP PIN is locked after too many wrong attempts. " +
                        "The only recovery is to erase all TOTP profiles on the key.")
                    .setPositiveButton("OK", null).show()
                is PinResult.Unsupported -> toast("OTP PIN command failed: ${result.detail}")
                PinResult.WrongTransport -> toast("OTP PIN needs the CCID/NFC transport (not USB-HID).")
                is PinResult.Failure -> toast("Failed: ${result.message}")
            }
        }
    }

    /** Arm a PIN op and prompt for a tap (works over NFC or USB-CCID). */
    private fun armPin(op: com.token2.lkcompanion.token2ui.Token2PinRepository.PendingOp,
                       overlaySub: String) {
        pinRepo.arm(op)
        pinPending = true
        showNfcOverlay("Present your key", overlaySub)
        // If a key is already on USB, drive it now.
        if (connectedUsbDevice != null) rereadUsbForCurrentTab()
    }

    private fun showPinStatusDialog(flag: com.token2.lkcompanion.token2.Token2Client.PinFlag) {
        val savedNote = if (rememberedOtpPin != null) "\n\nA PIN is remembered until the app closes." else ""
        val msg = if (flag.isSet)
            "OTP PIN: set\nLength: ${flag.pinLen} byte(s)\n" +
                "Retries left: ${flag.retriesLeft} of ${flag.maxRetries}" + savedNote
        else "OTP PIN: not set"
        val b = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("OTP PIN status")
            .setMessage(msg)
            .setNegativeButton("Close", null)
        if (flag.isSet) {
            b.setPositiveButton("Change") { _, _ -> promptChangePin() }
            b.setNeutralButton("Remove") { _, _ -> promptRemovePin() }
        } else {
            b.setPositiveButton("Set PIN") { _, _ -> promptSetPin() }
        }
        b.show()
        // (To forget a remembered PIN, use the "Forget remembered PIN" menu item.)
    }

    /** A single masked PIN input dialog. onOk gets the entered string. */
    // Persisted keypad-type preference (numeric vs full keyboard), like the FIDO2
    // PIN entry. Stored in SharedPreferences so it survives app restarts.
    private val pinPrefs by lazy { getSharedPreferences("otp_pin_prefs", MODE_PRIVATE) }
    private var pinAlphaMode: Boolean
        get() = pinPrefs.getBoolean("alpha_keypad", false)
        set(v) { pinPrefs.edit().putBoolean("alpha_keypad", v).apply() }

    // Optional remembered OTP PIN — held in memory only (like the FIDO2 PIN),
    // never written to disk. Survives while the app runs so codes unlock without
    // re-typing, but is gone when the app is closed.
    @Volatile private var rememberedOtpPin: String? = null

    // OTP-tab lock button state: whether the current key is PIN-protected, and
    // whether we currently hold a verified PIN for it.
    @Volatile private var otpProtected = false
    @Volatile private var otpUnlocked = false

    /**
     * A PIN entry dialog reusing the shared dialog_pin layout, with the
     * numeric/full-keyboard switch pre-set from the remembered preference and
     * saved when changed. `fields` picks which of the three inputs are shown.
     * `onOk` receives (old, new, confirm) — unused fields come back blank.
     */
    private fun pinDialog(
        title: String,
        showOld: Boolean,
        showConfirm: Boolean,
        showNew: Boolean = true,
        newHint: String? = null,
        onOk: (old: String, new: String, confirm: String) -> Unit,
    ) {
        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        val tilOld = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilOld)
        val tilNew = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilNew)
        val tilConfirm = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilConfirm)
        val oldField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinOld)
        val newField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinNew)
        val confirmField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinConfirm)
        val switchAlpha = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchAlpha)
        val switchRemember = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchRemember)
        switchRemember.visibility = View.GONE   // OTP PIN isn't cached in-session here

        tilOld.visibility = if (showOld) View.VISIBLE else View.GONE
        tilNew.visibility = if (showNew) View.VISIBLE else View.GONE
        tilConfirm.visibility = if (showConfirm) View.VISIBLE else View.GONE
        if (newHint != null) tilNew.hint = newHint

        // Apply the remembered keypad type up-front, and persist changes.
        switchAlpha.isChecked = pinAlphaMode
        setAlphaMode(oldField, pinAlphaMode)
        setAlphaMode(newField, pinAlphaMode)
        setAlphaMode(confirmField, pinAlphaMode)
        switchAlpha.setOnCheckedChangeListener { _, checked ->
            pinAlphaMode = checked   // remember it
            setAlphaMode(oldField, checked)
            setAlphaMode(newField, checked)
            setAlphaMode(confirmField, checked)
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(title)
            .setView(view)
            .setPositiveButton("OK") { _, _ ->
                onOk(
                    oldField.text?.toString() ?: "",
                    newField.text?.toString() ?: "",
                    confirmField.text?.toString() ?: "",
                )
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun promptSetPin() {
        pinDialog("Set OTP PIN", showOld = false, showConfirm = true) { _, new, confirm ->
            val err = com.token2.lkcompanion.token2.Token2PinValidator.validate(new)
            if (err != null) { toast(err); return@pinDialog }
            if (new != confirm) { toast("PINs did not match."); return@pinDialog }
            armPin(com.token2.lkcompanion.token2ui.Token2PinRepository.PendingOp.SetPin(new),
                "Setting OTP PIN…")
        }
    }

    private fun promptChangePin() {
        pinDialog("Change OTP PIN", showOld = true, showConfirm = true) { old, new, confirm ->
            if (old.isBlank()) { toast("Enter your current PIN."); return@pinDialog }
            val err = com.token2.lkcompanion.token2.Token2PinValidator.validate(new)
            if (err != null) { toast(err); return@pinDialog }
            if (new != confirm) { toast("New PINs did not match."); return@pinDialog }
            armPin(com.token2.lkcompanion.token2ui.Token2PinRepository.PendingOp
                .ChangePin(old, new), "Changing OTP PIN…")
        }
    }

    private fun promptRemovePin() {
        pinDialog("Remove OTP PIN", showOld = true, showConfirm = false, showNew = false) { old, _, _ ->
            if (old.isBlank()) { toast("Enter your current PIN."); return@pinDialog }
            com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle("Remove PIN?")
                .setMessage("This removes PIN protection from the key's TOTP store.")
                .setPositiveButton("Remove") { _, _ ->
                    armPin(com.token2.lkcompanion.token2ui.Token2PinRepository.PendingOp
                        .RemovePin(old), "Removing OTP PIN…")
                }
            .setNegativeButton("Cancel", null)
            .show()
    }
    }

    /**
     * A PIN-protected key returned "not verified" on read. Prompt for the PIN
     * (with the remembered keypad type), stash it, re-arm a refresh, and prompt a
     * re-tap so enumerate opens the verify window on the next session.
     */
    private fun promptUnlockPin() {
        // If a PIN is remembered, use it silently — no prompt.
        rememberedOtpPin?.let { saved ->
            repo.supplyPin(saved)
            repo.arm(Token2Repository.PendingOp.Refresh)
            showNfcOverlay("Present your key", "Unlocking codes…")
            if (connectedUsbDevice != null) rereadUsbForCurrentTab()
            return
        }

        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        view.findViewById<View>(R.id.tilOld).visibility = View.GONE
        view.findViewById<View>(R.id.tilConfirm).visibility = View.GONE
        // Hide the shared layout's session-only "remember" row (its notice says
        // "never saved to disk", which wouldn't match a persisted OTP PIN). We add
        // our own accurately-worded checkbox below instead.
        (view.findViewById<View>(R.id.switchRemember).parent as? View)?.visibility = View.GONE
        val til = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilNew)
        til.hint = "OTP PIN"
        val field = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinNew)
        val switchAlpha = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchAlpha)
        switchAlpha.isChecked = pinAlphaMode
        setAlphaMode(field, pinAlphaMode)
        switchAlpha.setOnCheckedChangeListener { _, checked ->
            pinAlphaMode = checked; setAlphaMode(field, checked)
        }

        // Our own remember checkbox, appended under the inflated view.
        val rememberBox = android.widget.CheckBox(this).apply {
            text = "Remember PIN until app closes"
        }
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            addView(view)
            val pad = (24 * resources.displayMetrics.density).toInt()
            addView(rememberBox, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                    setMargins(pad, 0, pad, 0)
                })
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Enter OTP PIN")
            .setMessage("This key's TOTP codes are PIN-protected. Enter the PIN, then " +
                "present the key again to unlock.")
            .setView(container)
            .setPositiveButton("Unlock") { _, _ ->
                val pin = field.text?.toString() ?: ""
                if (pin.isBlank()) { toast("Enter your OTP PIN."); return@setPositiveButton }
                if (rememberBox.isChecked) rememberedOtpPin = pin
                repo.supplyPin(pin)
                repo.arm(Token2Repository.PendingOp.Refresh)
                showNfcOverlay("Present your key", "Unlocking codes…")
                if (connectedUsbDevice != null) rereadUsbForCurrentTab()
            }
            .setNegativeButton("Cancel") { _, _ ->
                repo.clearPin()
                armedHint.text = "Codes are PIN-protected — unlock to view."
            }
            .show()
    }

    /** Reflect OTP protected/unlocked state on the lock button. */
    private fun updateOtpLockButton() {
        val btn = findViewById<android.widget.ImageButton>(R.id.btnOtpLock)
        if (!otpProtected) { btn.visibility = View.GONE; return }
        btn.visibility = View.VISIBLE
        btn.setImageResource(if (otpUnlocked) R.drawable.ic_lock_open else R.drawable.ic_lock)
        btn.contentDescription = getString(
            if (otpUnlocked) R.string.otp_lock_toggle else R.string.otp_lock_toggle)
    }

    /** OTP read via the standard OATH applet. Swaps the OTP list to the OATH adapter. */
    private fun readOath(transport: SmartCardTransport) {
        val hadPendingOperation = oathRepo.hasPendingOperation()
        val result = oathRepo.executeOn(transport)
        val operationStillPending = oathRepo.hasPendingOperation()
        otpIsOath = true
        runOnUiThread {
            if (otpList.adapter !== oathAdapter) otpList.adapter = oathAdapter
            hideNfcOverlay()
            when (result) {
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.Success -> {
                    oathAdapter.submit(result.entries)
                    val countText = "${result.entries.size} entr" +
                        if (result.entries.size == 1) "y." else "ies."
                    armedHint.text = "${result.message}. $countText"
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.DuplicateExists -> {
                    oathAdapter.submit(result.entries)
                    com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                        .setTitle("Entry already exists")
                        .setMessage("\"${result.existingLabel}\" is already on the key. Overwrite it?")
                        .setPositiveButton("Overwrite") { _, _ ->
                            startOathOperation(
                                com.token2.lkcompanion.oathui.OathRepository.PendingOp.Add(
                                    result.cred,
                                    allowOverwrite = true,
                                    expectedBackend = oathRepo.activeBackend,
                                ),
                                "replace ${result.cred.account}",
                            ) {
                                showNfcOverlay(
                                    "Hold your key to the phone",
                                    "Replacing ${result.cred.account}…",
                                )
                            }
                        }
                        .setNegativeButton("Cancel") { _, _ ->
                            oathRepo.cancelPending()
                            armedHint.text = "Add cancelled — entry already exists."
                        }
                        .show()
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.Failure -> {
                    armedHint.text = when {
                        hadPendingOperation && operationStillPending ->
                            "Operation still pending: ${result.message}"
                        hadPendingOperation -> "Operation cancelled: ${result.message}"
                        else -> "Failed: ${result.message}"
                    }
                    if (hadPendingOperation && operationStillPending) {
                        showPendingOathRecovery(result.message)
                    }
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.PasswordRequired -> {
                    armedHint.text = if (result.wrongPassword) {
                        "Wrong OATH password."
                    } else {
                        "This key's OATH accounts are password protected."
                    }
                    promptOathPassword(result)
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.TouchTimeout -> {
                    armedHint.text =
                        "The key did not confirm the OTP operation. Retry to continue safely."
                    showFeitianTouchRetry(result.message)
                }
                com.token2.lkcompanion.oathui.OathRepository.OpResult.NotAnOathKey -> {
                    if (hadPendingOperation && operationStillPending) {
                        armedHint.text = "Operation still pending: use the original OTP key."
                        showPendingOathRecovery(
                            "The presented key does not provide the required OTP backend."
                        )
                    } else if (hadPendingOperation) {
                        armedHint.text =
                            "OTP operation cancelled: the presented key uses a different backend."
                    } else {
                        armedHint.text = "No OTP applet (Token2, OATH, or Feitian) on this key."
                    }
                }
            }
        }
    }

    /**
     * Ask for the OATH password, then resume the still-armed operation. Nothing
     * is sent to the key from here: the derived access key is cached and the
     * next connection unlocks the applet before its first command.
     */
    private fun promptOathPassword(
        result: com.token2.lkcompanion.oathui.OathRepository.OpResult.PasswordRequired,
    ) {
        val input = android.widget.EditText(this).apply {
            hint = "OATH password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val pad = (16 * resources.displayMetrics.density).toInt()
        val wrap = android.widget.FrameLayout(this).apply {
            setPadding(pad + pad, pad, pad + pad, 0); addView(input)
        }
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(if (result.wrongPassword) "Wrong password" else "OATH password required")
            .setMessage(
                (if (result.wrongPassword) "The key rejected that password. " else "") +
                    "This key's OATH accounts are protected by a password. Entering it " +
                    "does not consume any retry counter. It is kept only while the key " +
                    "stays connected."
            )
            .setView(wrap)
            .setPositiveButton("Unlock", null)   // set below, to survive an empty entry
            .setNegativeButton("Cancel") { _, _ ->
                oathRepo.cancelPending()
                armedHint.text = "OATH is locked — password not entered."
            }
            .create()
        dialog.setOnCancelListener { oathRepo.cancelPending() }
        dialog.setOnDismissListener {
            if (otpOperationDialog === dialog) otpOperationDialog = null
        }
        dialog.setOnShowListener {
            dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val password = input.text.toString()
                if (password.isEmpty()) {
                    toast("Enter the key's OATH password.")
                    return@setOnClickListener
                }
                oathRepo.rememberPassword(result.deviceIdHex, password)
                dialog.dismiss()
                showNfcOverlay("Hold your key to the phone", "Unlocking OATH…")
            }
        }
        otpOperationDialog?.dismiss()
        otpOperationDialog = dialog
        dialog.show()
    }

    /** Retry a timed-out Feitian operation while the repository still holds it. */
    private fun showFeitianTouchRetry(message: String) {
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Touch not detected")
            .setMessage(
                "$message\n\nTap Retry, then touch and hold the key when its LED blinks."
            )
            .setPositiveButton("Retry") { _, _ ->
                showNfcOverlay("Hold your key to the phone", "Retrying OTP operation…")
            }
            .setNegativeButton("Cancel") { _, _ ->
                oathRepo.cancelPending()
            }
            .create()
        dialog.setOnCancelListener {
            oathRepo.cancelPending()
        }
        dialog.setOnDismissListener {
            if (otpOperationDialog === dialog) otpOperationDialog = null
        }
        otpOperationDialog?.dismiss()
        otpOperationDialog = dialog
        dialog.show()
    }

    /** A replacement cleanup survives wrong-key taps; make that retained state explicit. */
    private fun showPendingOathRecovery(message: String) {
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Use the original OTP key")
            .setMessage(
                "$message\n\nThe recovery operation remains pending. Present the key that " +
                    "started it, or cancel the operation."
            )
            .setPositiveButton("Keep pending", null)
            .setNegativeButton("Cancel operation") { _, _ ->
                oathRepo.cancelPending()
                armedHint.text = "OTP operation cancelled."
            }
            .create()
        dialog.setOnDismissListener {
            if (otpOperationDialog === dialog) otpOperationDialog = null
        }
        otpOperationDialog?.dismiss()
        otpOperationDialog = dialog
        dialog.show()
    }

    /** Convert an import according to the backend selected when Add was opened. */
    private fun entryToOathCredential(
        e: com.token2.lkcompanion.token2.Token2Codec.Entry,
        backend: com.token2.lkcompanion.oathui.OathRepository.BackendKind,
    ):
            com.token2.lkcompanion.oath.OathCredential {
        val algo = when (e.algorithm) {
            com.token2.lkcompanion.token2.Token2Codec.ALG_SHA256 -> com.token2.lkcompanion.oath.OathCore.HashAlgo.SHA256
            else -> com.token2.lkcompanion.oath.OathCore.HashAlgo.SHA1
        }
        return com.token2.lkcompanion.oath.OathCredential(
            issuer = e.appName.ifBlank { null },
            account = e.accountName,
            secret = e.seed ?: ByteArray(0),
            type = if (e.isTotp) {
                com.token2.lkcompanion.oath.OathCredential.Type.TOTP
            } else {
                com.token2.lkcompanion.oath.OathCredential.Type.HOTP
            },
            algo = algo,
            digits = backend.normalizeImportedDigits(e.codeLength),
            period = if (e.timestep > 0) e.timestep else 30,
        )
    }

    private fun confirmDeleteOath(d: com.token2.lkcompanion.oathui.OathRepository.Display) {
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Delete entry?")
            .setMessage("Remove \"${if (d.issuer.isBlank()) d.account else d.issuer + " / " + d.account}\" " +
                "from the key permanently?")
            .setPositiveButton("Delete") { _, _ ->
                startOathOperation(
                    com.token2.lkcompanion.oathui.OathRepository.PendingOp.Delete(d),
                    "delete ${d.account}",
                ) {
                    showNfcOverlay("Hold your key to the phone", "Deleting ${d.account}…")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun calculateOath(d: com.token2.lkcompanion.oathui.OathRepository.Display) {
        if (d.backend != com.token2.lkcompanion.oathui.OathRepository.BackendKind.FEITIAN) {
            return
        }
        startOathOperation(
            com.token2.lkcompanion.oathui.OathRepository.PendingOp.Calculate(d),
            "calculate ${d.account}",
        ) {
            showNfcOverlay("Hold your key to the phone", "Calculating ${d.account}…")
        }
    }

    /** Info tab tap: identify every applet and render the overview, with tap-to-manage. */
    private fun runInfoTap(transport: SmartCardTransport) {
        Thread { try { readInfoOverlay(transport) } finally { transport.close() } }.start()
    }

    /** Blocking applet identify + overview render. Caller owns transport lifecycle. */
    private fun readInfoOverlay(transport: SmartCardTransport,
                                usbDevice: android.hardware.usb.UsbDevice? = null) {
        val rows = ArrayList<StatusCard.Row>()
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_contactless,
            label = "Connected",
            secondary = transport.displayName,
            chipText = "OK", chipState = StatusCard.State.SUCCESS,
        ))
        rows.add(oathInfoRow(transport))
        rows.add(token2InfoRow(transport))
        rows.add(fido2InfoRow(transport, usbDevice))
        rows.add(openPgpInfoRow(transport))
        rows.add(pivInfoRow(transport))
        runOnUiThread { hideNfcOverlay(); infoStatusCard.render(rows) }
    }

    /** Preserve the YKOATH status row, with Feitian as its ordered fallback. */
    private fun oathInfoRow(transport: SmartCardTransport): StatusCard.Row {
        try {
            val applet = OathApplet(transport)
            val info = applet.select()
            oathRepo.noteDetectedBackend(
                com.token2.lkcompanion.oathui.OathRepository.BackendKind.YKOATH
            )
            // A password-protected applet answers SELECT but refuses LIST (6982).
            // Report it as locked; the OTP tab prompts for the password.
            if (!oathRepo.tryUnlock(applet, info)) return otpLockedRow("OATH OTP")
            val entries = applet.list()
            return otpPresentRow("OATH OTP", entries.size)
        } catch (_: AppletUnavailableException) {
            // Probe the next protocol.
        } catch (_: Exception) {
            return otpUnavailableRow("OATH OTP")
        }

        try {
            val applet = FeitianOtpApplet(transport)
            applet.select()
            val entries = applet.list()
            oathRepo.noteDetectedBackend(
                com.token2.lkcompanion.oathui.OathRepository.BackendKind.FEITIAN,
            )
            return otpPresentRow("Feitian OTP", entries.size)
        } catch (_: AppletUnavailableException) {
            return otpUnavailableRow("OATH OTP")
        } catch (e: Exception) {
            return otpProbeErrorRow("Feitian OTP", e)
        }
    }

    /** Original Token2 status row; Feitian probing does not replace or relabel it. */
    private fun token2InfoRow(transport: SmartCardTransport): StatusCard.Row = try {
        val client = com.token2.lkcompanion.token2.Token2Client.overNfc(transport)
        val count = try {
            client.enumerate(System.currentTimeMillis() / 1000).size
        } catch (_: com.token2.lkcompanion.token2.Token2Exception.EntryNotFound) {
            0
        } catch (_: com.token2.lkcompanion.token2.Token2Exception.PinNotVerified) {
            // Protected key: can't count without the PIN. Show a protected row that
            // sends the user to the OTP tab to unlock, rather than an error.
            return StatusCard.Row(
                R.drawable.ic_timer,
                "On-device OTP",
                "PIN-protected · tap to unlock",
                chipText = "Protected",
                chipState = StatusCard.State.WARNING,
                onClick = { goToTab(Mode.TOTP, R.id.nav_totp) },
            )
        }
        StatusCard.Row(
            R.drawable.ic_timer,
            "On-device OTP",
            "$count entry(s) · tap to manage",
            chipText = "Present",
            chipState = StatusCard.State.SUCCESS,
            onClick = { goToTab(Mode.TOTP, R.id.nav_totp) },
        )
    } catch (e: Exception) {
        val message = e.message.orEmpty()
        if (listOf("6A82", "6A86", "6D00", "6999").any(message::contains)) {
            otpUnavailableRow("On-device OTP")
        } else {
            StatusCard.Row(
                R.drawable.ic_timer,
                "On-device OTP",
                "error",
                chipText = "Error",
                chipState = StatusCard.State.DANGER,
            )
        }
    }

    private fun otpPresentRow(label: String, count: Int) = StatusCard.Row(
        R.drawable.ic_timer,
        label,
        "$count credential(s) · tap to manage",
        chipText = "Present",
        chipState = StatusCard.State.SUCCESS,
        onClick = { goToTab(Mode.TOTP, R.id.nav_totp) },
    )

    private fun otpLockedRow(label: String) = StatusCard.Row(
        R.drawable.ic_timer,
        label,
        "password protected · tap to unlock",
        chipText = "Locked",
        chipState = StatusCard.State.WARNING,
        onClick = { goToTab(Mode.TOTP, R.id.nav_totp) },
    )

    private fun otpUnavailableRow(label: String) = StatusCard.Row(
        R.drawable.ic_timer,
        label,
        "not on this key",
        chipText = "—",
        chipState = StatusCard.State.NEUTRAL,
        dimmed = true,
    )

    private fun otpProbeErrorRow(label: String, error: Exception) = StatusCard.Row(
        R.drawable.ic_timer,
        label,
        error.message ?: "probe failed",
        chipText = "Error",
        chipState = StatusCard.State.DANGER,
    )

    /** FIDO2 row for the Info overview — taps through to the FIDO tab. */
    private fun fido2InfoRow(transport: SmartCardTransport,
                             usbDevice: android.hardware.usb.UsbDevice? = null): StatusCard.Row = try {
        val info = com.token2.lkcompanion.fido.ctap.Ctap2Client(transport).getInfo()
        val mdsEntry = mds.lookup(info.aaguidHex)
        val mdsIcon = com.token2.lkcompanion.fido.MdsRepository.decodeIcon(mdsEntry?.iconDataUri)
        if (info.isFido2) {
            // If MDS recognizes this key, lead with the device name + certification
            // (and its logo); otherwise fall back to the generic FIDO2 label.
            val label = mdsEntry?.name ?: "FIDO2"
            val secondary = if (mdsEntry != null)
                certLabel(mdsEntry.certification) + " · tap to manage"
            else "passkeys, PIN · tap to manage"
            StatusCard.Row(R.drawable.ic_key, label, secondary,
                iconBitmap = mdsIcon,
                chipText = "Present", chipState = StatusCard.State.SUCCESS,
                onClick = { goToTab(Mode.FIDO, R.id.nav_fido) })
        } else
            StatusCard.Row(R.drawable.ic_key, "FIDO2", "U2F only",
                chipText = "U2F", chipState = StatusCard.State.NEUTRAL, dimmed = true)
    } catch (e: Exception) {
        val msg = e.message ?: e.javaClass.simpleName
        // Over USB CCID the FIDO applet is unreachable (SW 6A81) — it lives on the
        // HID interface. Read the AAGUID over CTAPHID from the same USB device so the
        // overview still shows the MDS name / certification / icon. Fall back to a
        // prior FIDO-tab read's cached AAGUID if a direct read isn't possible.
        if (msg.contains("6A81") || msg.contains("0xFF")) {
            var aaguid: String? = fidoRepo.lastInfo?.aaguidHex
            if (usbDevice != null) {
                val conn = usbManager.openDevice(usbDevice)
                val wire = if (conn != null)
                    com.token2.lkcompanion.fido.ctap.CtapHidWire.find(conn, usbDevice) else null
                if (wire != null) {
                    aaguid = try {
                        com.token2.lkcompanion.fido.ctap.Ctap2Client(wire).getInfo().aaguidHex
                    } catch (_: Exception) { aaguid }
                }
                conn?.close()
            }
            val mdsEntry = mds.lookup(aaguid)
            val mdsIcon = com.token2.lkcompanion.fido.MdsRepository.decodeIcon(mdsEntry?.iconDataUri)
            StatusCard.Row(R.drawable.ic_key,
                iconBitmap = mdsIcon,
                label = mdsEntry?.name ?: "FIDO2",
                secondary = if (mdsEntry != null)
                    certLabel(mdsEntry.certification) + " · open FIDO2 tab (USB uses HID)"
                else "open FIDO2 tab (USB uses HID)",
                chipText = "HID", chipState = StatusCard.State.SUCCESS,
                onClick = { goToTab(Mode.FIDO, R.id.nav_fido) })
        } else
            StatusCard.Row(R.drawable.ic_key, "FIDO2", "not on this key",
                chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
    }

    /** Switch tabs programmatically. Setting selectedItemId fires the nav listener,
     *  which arms + re-reads — so we must NOT also do it here (double-trigger race). */
    private fun goToTab(m: Mode, navId: Int) {
        val nav = findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(
            R.id.bottomNav)
        if (nav.selectedItemId == navId) {
            // Already on that tab id; the listener won't fire, so do it directly.
            mode = m; showPane(m)
            if (m == Mode.TOTP) {
                if (armOtpRefresh()) rereadUsbForCurrentTab()
            } else {
                if (m == Mode.FIDO) fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
                rereadUsbForCurrentTab()
            }
        } else {
            nav.selectedItemId = navId   // fires listener -> sets mode, arms, re-reads
        }
    }

    /**
     * If a USB key is plugged in, re-run the current tab's read against it. Unlike
     * NFC (re-tap each time), a USB device stays connected, so switching tabs needs
     * an explicit re-read to populate the new tab. No-op when nothing is connected
     * (NFC users just tap again).
     */
    private fun rereadUsbForCurrentTab() {
        val device = connectedUsbDevice ?: run {
            // Nothing connected over USB — NFC users just tap again.
            return
        }
        if (!usbManager.hasPermission(device)) { requestUsbPermission(device); return }
        // openUsb is serialized + guarded; it reads for the now-current mode.
        openUsb(device)
    }

    /** Probe one applet -> status row. Non-manageable applets render "view only". */
    private inline fun appletRow(
        name: String, iconRes: Int, manageable: Boolean = false, block: () -> String,
    ): StatusCard.Row =
        try {
            val detail = block()
            StatusCard.Row(iconRes, name,
                secondary = if (manageable) detail else "$detail · view only",
                chipText = "Present", chipState = StatusCard.State.SUCCESS)
        } catch (e: Exception) {
            val msg = e.message ?: e.javaClass.simpleName
            val absent = listOf("6A82", "6A86", "6D00", "6999", "6A81", "6A80").any { msg.contains(it) }
            if (absent)
                StatusCard.Row(iconRes, name, secondary = "not on this key",
                    chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
            else
                StatusCard.Row(iconRes, name, secondary = "SW $msg".take(40),
                    chipText = "Error", chipState = StatusCard.State.DANGER)
        }

    /** PIV overview row: version + cert count, tappable to a full detail dialog. */
    private fun pivInfoRow(transport: SmartCardTransport): StatusCard.Row = try {
        val s = PivApplet(transport).status()
        cachedPivStatus = s
        val retries = buildString {
            if (s.pinRetries != null) append(" · PIN ${s.pinRetries}")
        }
        StatusCard.Row(R.drawable.ic_id, "PIV",
            secondary = "v${s.version ?: "?"} · ${s.slotsWithCert.size} cert(s)$retries · tap for details",
            chipText = "Present", chipState = StatusCard.State.SUCCESS,
            onClick = { showPivDetails() })
    } catch (e: Exception) {
        val msg = e.message ?: e.javaClass.simpleName
        val absent = listOf("6A82", "6A86", "6D00", "6999", "6A81", "6A80").any { msg.contains(it) }
        if (absent)
            StatusCard.Row(R.drawable.ic_id, "PIV", secondary = "not on this key",
                chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
        else
            StatusCard.Row(R.drawable.ic_id, "PIV", secondary = "SW $msg".take(40),
                chipText = "Error", chipState = StatusCard.State.DANGER)
    }

    /** Full PIV detail dialog: per-slot certificate fields, retry counts, card GUID. */
    private fun showPivDetails() {
        val s = cachedPivStatus ?: return
        val sb = StringBuilder()
        sb.append("Applet version: ${s.version ?: "unknown"}\n")
        s.cardGuidHex?.let { sb.append("Card GUID: ${formatGuid(it)}\n") }
        val pin = s.pinRetries?.let { "$it left" } ?: "—"
        val puk = s.pukRetries?.let { "$it left" } ?: "—"
        sb.append("PIN retries: $pin    PUK retries: $puk\n")
        sb.append("\n")
        if (s.certs.isEmpty()) {
            sb.append(if (s.slotsWithCert.isEmpty()) "No certificates in any slot."
                      else "Slots with data: ${s.slotsWithCert.joinToString(", ")}\n(certificate parsing unavailable)")
        } else {
            for (c in s.certs) {
                val ci = c.info
                sb.append("■ ${c.slot}\n")
                ci.subjectCn?.let { sb.append("   Subject: $it\n") }
                ci.issuerCn?.let { sb.append("   Issuer: $it\n") }
                ci.keyAlgorithm?.let { sb.append("   Key: $it\n") }
                if (ci.notBefore != null || ci.notAfter != null)
                    sb.append("   Valid: ${ci.notBefore ?: "?"} → ${ci.notAfter ?: "?"}\n")
                ci.serialHex?.let { sb.append("   Serial: ${it.chunked(2).joinToString(":")}\n") }
                sb.append("   SHA-256: ${ci.sha256Fingerprint}\n")
                sb.append("\n")
            }
        }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("PIV details")
            .setMessage(sb.toString().trimEnd())
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy") { _, _ -> copyToClipboard("PIV details", sb.toString().trimEnd()) }
            .show()
    }

    /** OpenPGP overview row: key count + retries, tappable to full detail. */
    private fun openPgpInfoRow(transport: SmartCardTransport): StatusCard.Row = try {
        val s = OpenPgpApplet(transport).status()
        cachedPgpStatus = s
        val keyCount = s.keys.count { it.present }
        val retries = if (s.pin1Retries != null) " · PIN ${s.pin1Retries}" else ""
        StatusCard.Row(R.drawable.ic_lock, "OpenPGP",
            secondary = "$keyCount/3 keys$retries · tap for details",
            chipText = "Present", chipState = StatusCard.State.SUCCESS,
            onClick = { showOpenPgpDetails() })
    } catch (e: Exception) {
        val msg = e.message ?: e.javaClass.simpleName
        val absent = listOf("6A82", "6A86", "6D00", "6999", "6A81", "6A80").any { msg.contains(it) }
        if (absent)
            StatusCard.Row(R.drawable.ic_lock, "OpenPGP", secondary = "not on this key",
                chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
        else
            StatusCard.Row(R.drawable.ic_lock, "OpenPGP", secondary = "SW $msg".take(40),
                chipText = "Error", chipState = StatusCard.State.DANGER)
    }

    /** Full OpenPGP detail dialog: per-slot key existence, algorithm, date, fingerprint. */
    private fun showOpenPgpDetails() {
        val s = cachedPgpStatus ?: return
        val sb = StringBuilder()
        sb.append("Spec: ${s.specVersion}\n")
        s.serialHex?.let { sb.append("Card serial: $it\n") }
        s.cardholderName?.let { sb.append("Cardholder: $it\n") }
        s.url?.takeIf { it.isNotBlank() }?.let { sb.append("URL: $it\n") }
        val pin1 = s.pin1Retries?.let { "$it left" } ?: "—"
        val pin3 = s.pin3Retries?.let { "$it left" } ?: "—"
        sb.append("PIN (PW1): $pin1    Admin (PW3): $pin3\n\n")
        for (k in s.keys) {
            sb.append("■ ${k.name}\n")
            if (!k.present) {
                sb.append("   (no key)\n\n")
            } else {
                k.algorithm?.let { sb.append("   Algorithm: $it\n") }
                k.generated?.let { sb.append("   Generated: $it\n") }
                k.fingerprint?.let { sb.append("   Fingerprint: ${it.chunked(4).joinToString(" ")}\n") }
                sb.append("\n")
            }
        }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("OpenPGP details")
            .setMessage(sb.toString().trimEnd())
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy") { _, _ -> copyToClipboard("OpenPGP details", sb.toString().trimEnd()) }
            .show()
    }

    /** Format a 16-byte GUID hex string as 8-4-4-4-12. */
    private fun formatGuid(hex: String): String {
        if (hex.length != 32) return hex
        return "${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-" +
               "${hex.substring(16,20)}-${hex.substring(20)}"
    }

    // --- NFC tap overlay ---
    private fun startOathOperation(
        op: com.token2.lkcompanion.oathui.OathRepository.PendingOp,
        operation: String,
        start: () -> Unit,
    ): Boolean {
        if (repo.pending !is Token2Repository.PendingOp.Refresh ||
            usbBusy || otpOperationDialog != null || !oathRepo.tryArm(op)) {
            toast("Another OTP operation is already in progress.")
            return false
        }
        runFeitianTouchAware(operation, start)
        return true
    }

    /**
     * Feitian's USB OTP applet requires physical presence for CALCULATE and
     * mutating commands. Give the user time to prepare before the short token
     * timeout starts; LIST itself does not require touch.
     */
    private fun runFeitianTouchAware(
        operation: String,
        start: () -> Unit,
    ) {
        val isFeitian = oathRepo.activeBackend ==
            com.token2.lkcompanion.oathui.OathRepository.BackendKind.FEITIAN
        val shouldPrompt = connectedUsbDevice != null && isFeitian
        if (!shouldPrompt) {
            start()
            return
        }

        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Touch Feitian key")
            .setMessage(
                "After tapping Continue, touch and hold the key when its LED blinks " +
                    "to $operation. The request expires after a few seconds."
            )
            .setPositiveButton("Continue") { _, _ -> start() }
            .setNegativeButton("Cancel") { _, _ ->
                oathRepo.cancelPending()
            }
            .create()
        dialog.setOnCancelListener {
            oathRepo.cancelPending()
        }
        dialog.setOnDismissListener {
            if (otpOperationDialog === dialog) otpOperationDialog = null
        }
        otpOperationDialog = dialog
        dialog.show()
    }

    /**
     * Called after an operation is armed. If a USB key is connected, run the read
     * immediately over USB (no tap needed). Otherwise show the NFC tap overlay and
     * wait for the user to tap.
     */
    private fun showNfcOverlay(title: String, subtitle: String) {
        val device = connectedUsbDevice
        if (device != null && usbManager.hasPermission(device)) {
            openUsb(device)   // serialized; reads for the current mode
            return
        }
        runOnUiThread {
            nfcOverlayTitle.text = title
            nfcOverlaySubtitle.text = subtitle
            nfcOverlay.visibility = View.VISIBLE
            val pulse = android.view.animation.AnimationUtils
                .loadAnimation(this, R.anim.nfc_pulse)
            nfcPulseCircle.startAnimation(pulse)
        }
    }

    private fun hideNfcOverlay() {
        runOnUiThread {
            nfcPulseCircle.clearAnimation()
            nfcOverlay.visibility = View.GONE
        }
    }

    /** Confirm before a destructive delete; arms + shows overlay only on confirm. */
    private fun confirmDelete(entry: com.token2.lkcompanion.token2.Token2Codec.Entry) {
        val label = if (entry.appName.isBlank()) entry.accountName
            else "${entry.appName} / ${entry.accountName}"
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Delete entry?")
            .setMessage("Remove \"$label\" from the key permanently? " +
                "This can't be undone.")
            .setPositiveButton("Delete") { _, _ ->
                repo.arm(Token2Repository.PendingOp.Delete(entry.appName, entry.accountName))
                showNfcOverlay("Hold your key to the phone", "Deleting $label…")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun renderFidoCard(i: com.token2.lkcompanion.fido.ctap.Ctap2Client.Info, retries: Int?) {
        val rows = ArrayList<StatusCard.Row>()

        // aaguid — full value, with a copy button. If MDS knows this AAGUID, show
        // the friendly model name, certification level, and device icon.
        val mdsEntry = mds.lookup(i.aaguidHex)
        val mdsIcon = com.token2.lkcompanion.fido.MdsRepository.decodeIcon(mdsEntry?.iconDataUri)
        // Device row: MDS name, icon, and certification level (when matched).
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_key,
            iconBitmap = mdsIcon,
            label = mdsEntry?.name ?: "Security key",
            secondary = if (mdsEntry != null) certLabel(mdsEntry.certification) else null,
            chipText = if (i.isFido2) "FIDO2" else "U2F",
            chipState = if (i.isFido2) StatusCard.State.SUCCESS else StatusCard.State.NEUTRAL,
        ))

        // AAGUID — its own row with a copy button.
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_info,
            label = "AAGUID",
            secondary = i.aaguidHex ?: "unavailable",
            copyValue = i.aaguidHex,
            onCopy = if (i.aaguidHex != null) { v -> copyToClipboard("aaguid", v) } else null,
        ))

        // PIN — "Set" if none, "Change" if set
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_lock,
            label = "PIN",
            secondary = buildString {
                if (i.clientPinSet && retries != null) append("$retries retries left")
                if (fidoRepo.hasRememberedPin) { if (isNotEmpty()) append(" · "); append("remembered") }
            }.ifEmpty { null },
            chipText = if (i.clientPinSet) "Set" else "Not set",
            chipState = if (i.clientPinSet) StatusCard.State.SUCCESS else StatusCard.State.NEUTRAL,
            actionText = if (i.clientPinSet) "Change" else "Set",
            onAction = { promptPin() },
        ))

        // alwaysUV — On/Off chip + a Toggle button (only if supported)
        val alwaysUvSupported = i.supportsConfig || i.options["alwaysUv"] != null
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_shield,
            label = "Always require UV",
            secondary = if (alwaysUvSupported) null else "not supported",
            chipText = when {
                !alwaysUvSupported -> "N/A"
                i.alwaysUv -> "On"
                else -> "Off"
            },
            chipState = if (alwaysUvSupported && i.alwaysUv) StatusCard.State.SUCCESS
                        else StatusCard.State.NEUTRAL,
            actionText = if (alwaysUvSupported) "Toggle" else null,
            onAction = if (alwaysUvSupported) {
                {
                    if (!i.clientPinSet) {
                        toast("Set a PIN first — alwaysUV needs one.")
                    } else promptSinglePin("Toggle alwaysUV",
                        "Enter the key's PIN to toggle alwaysUV.") { pin ->
                        fidoRepo.arm(FidoRepository.PendingOp.ToggleAlwaysUv(pin))
                        showNfcOverlay("Hold your key to the phone", "Toggling alwaysUV…")
                    }
                }
            } else null,
        ))

        // Credential management — Manage button opens the passkey screen
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_id,
            label = "Credential management",
            secondary = "passkeys",
            chipText = if (i.supportsCredMgmt) "Yes" else "No",
            chipState = if (i.supportsCredMgmt) StatusCard.State.SUCCESS else StatusCard.State.NEUTRAL,
            actionText = if (i.supportsCredMgmt) "Manage" else null,
            onAction = if (i.supportsCredMgmt) { { openPasskeyScreen() } } else null,
        ))

        // Remaining discoverable-credential capacity (CTAP2.1 getInfo tag 0x14).
        // Only shown when the key reports it; older keys simply omit the row.
        i.remainingDiscCreds?.let { n ->
            rows.add(StatusCard.Row(
                iconRes = R.drawable.ic_key,
                label = "Passkey capacity",
                secondary = "$n more can be created",
                chipText = "$n",
                chipState = if (n > 0) StatusCard.State.SUCCESS else StatusCard.State.WARNING,
            ))
        }

        // Fingerprint enrollment — Manage opens the fingerprints screen.
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_fingerprint,
            label = "Fingerprints",
            secondary = "on-key biometric enrollment",
            chipText = if (i.supportsBioEnroll) "Yes" else "No",
            chipState = if (i.supportsBioEnroll) StatusCard.State.SUCCESS else StatusCard.State.NEUTRAL,
            dimmed = !i.supportsBioEnroll,
            actionText = if (i.supportsBioEnroll) "Manage" else null,
            onAction = if (i.supportsBioEnroll) { { openFingerprintScreen() } } else null,
        ))

        // Reset FIDO2 — erase all passkeys and clear the PIN (factory reset).
        rows.add(StatusCard.Row(
            iconRes = R.drawable.ic_warning,
            label = "Reset FIDO2",
            secondary = "erase all passkeys & PIN",
            chipText = "Danger",
            chipState = StatusCard.State.DANGER,
            actionText = "Reset",
            onAction = { confirmResetFido() },
        ))

        fidoStatusCard.render(rows)
    }

    private fun copyToClipboard(label: String, value: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText(label, value))
        toast("$label copied")
    }

    // --- passkey screen (separate full-screen view with back arrow) ---
    private fun openPasskeyScreen() {
        passkeyScreenOpen = true
        panePasskeys.visibility = View.VISIBLE
        passkeyAdapter.submit(fidoRepo.cachedPasskeys)
        passkeyHint.text = if (fidoRepo.cachedPasskeys.isEmpty())
            "Tap your key to load passkeys." else "Tap your key to refresh."
        // Arm a list operation so the next tap loads/refreshes passkeys.
        promptSinglePin("Load passkeys", "Enter the key's PIN to list passkeys.",
            onCancel = { closePasskeyScreen() }) { pin ->
            fidoRepo.arm(FidoRepository.PendingOp.ListPasskeys(pin))
            showNfcOverlay("Hold your key to the phone", "Reading passkeys…")
        }
    }

    private fun closePasskeyScreen() {
        passkeyScreenOpen = false
        panePasskeys.visibility = View.GONE
    }

    // --- FIDO2 reset ---
    private fun confirmResetFido() {
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Erase everything?")
            .setMessage("This permanently erases every passkey on the key and removes " +
                "its PIN. The key returns to a factory state and this cannot be undone.\n\n" +
                "Some keys only accept a reset within a few seconds of being connected — " +
                "if it fails, re-tap (or unplug and replug) the key and try again immediately.")
            .setPositiveButton("Erase everything") { _, _ ->
                fidoRepo.arm(FidoRepository.PendingOp.ResetFido)
                showNfcOverlay("Hold your key to the phone", "Resetting FIDO2…")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // --- fingerprints screen ---
    /** True when the PIN currently in fidoRepo was entered for this screen; dropped on exit. */
    @Volatile private var fpPinOwnedByScreen = false

    private fun openFingerprintScreen() {
        fpScreenOpen = true
        paneFingerprints.visibility = View.VISIBLE
        // Never show cached data here — fingerprint templates can be modified by
        // other clients (Chrome/Windows/Yubico tools), so always read from the key.
        fpAdapter.submit(emptyList())
        fpHint.text = "Verify the key's PIN to read fingerprints."
        // If a PIN is already remembered (e.g. the user opted in elsewhere), reuse it
        // as-is; only a PIN entered through this screen is dropped on close.
        fpPinOwnedByScreen = !fidoRepo.hasRememberedPin
        promptSinglePin("Load fingerprints",
            "Enter the key's PIN to list fingerprints.", pageScopedPin = true,
            onCancel = { closeFingerprintScreen() }) { pin ->
            fidoRepo.arm(FidoRepository.PendingOp.ListFingerprints(pin))
            showNfcOverlay("Hold your key to the phone", "Reading fingerprints…")
        }
    }

    private fun closeFingerprintScreen() {
        fpScreenOpen = false
        paneFingerprints.visibility = View.GONE
        if (fpPinOwnedByScreen) {
            fidoRepo.forgetPin()
            fpPinOwnedByScreen = false
        }
    }

    private fun promptRenameFingerprint(fp: com.token2.lkcompanion.fido.ctap.Ctap2Client.Fingerprint) {
        val view = layoutInflater.inflate(R.layout.dialog_text_input, null)
        val til = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilInput)
        til.hint = "Fingerprint name"
        val input = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etInput)
        input.setText(fp.name ?: "")
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Rename fingerprint")
            .setView(view)
            .setPositiveButton("Save") { _, _ ->
                val name = input.text?.toString()?.trim().orEmpty()
                if (name.isEmpty()) { toast("Name can't be empty"); return@setPositiveButton }
                val pin = fidoRepo.rememberedPin
                if (pin == null) {
                    promptSinglePin("Confirm with PIN", "Enter the key's PIN to rename.") { p ->
                        fidoRepo.arm(FidoRepository.PendingOp.RenameFingerprint(p, fp.templateId, name))
                        showNfcOverlay("Hold your key to the phone", "Renaming…")
                    }
                } else {
                    fidoRepo.arm(FidoRepository.PendingOp.RenameFingerprint(pin, fp.templateId, name))
                    showNfcOverlay("Hold your key to the phone", "Renaming…")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmRemoveFingerprint(fp: com.token2.lkcompanion.fido.ctap.Ctap2Client.Fingerprint) {
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Remove fingerprint?")
            .setMessage("Delete \"${fp.name ?: "this fingerprint"}\" from the key? This can't be undone.")
            .setPositiveButton("Remove") { _, _ ->
                val pin = fidoRepo.rememberedPin
                if (pin == null) {
                    promptSinglePin("Confirm with PIN", "Enter the key's PIN to remove.") { p ->
                        fidoRepo.arm(FidoRepository.PendingOp.RemoveFingerprint(p, fp.templateId))
                        showNfcOverlay("Hold your key to the phone", "Removing…")
                    }
                } else {
                    fidoRepo.arm(FidoRepository.PendingOp.RemoveFingerprint(pin, fp.templateId))
                    showNfcOverlay("Hold your key to the phone", "Removing…")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * Interactive fingerprint enrollment. Needs a connected USB key (the multi-touch
     * session holds the connection open). Drives the enrollBegin → captureNext loop
     * on the usbExecutor, posting live feedback to a progress dialog.
     */
    private fun startFingerprintEnroll() {
        val device = connectedUsbDevice
        if (device == null) {
            toast("Connect the key over USB to enroll a fingerprint.")
            return
        }
        val pin = fidoRepo.rememberedPin
        if (pin == null) {
            promptSinglePin("Enroll fingerprint", "Enter the key's PIN to start enrollment.") { p ->
                fidoRepo.rememberPin(p); runEnroll(device, p)
            }
        } else runEnroll(device, pin)
    }

    private fun runEnroll(device: UsbDevice, pin: String) {
        // Progress dialog with live feedback text.
        val msg = TextView(this).apply {
            text = "Touch the sensor with your finger…"
            setPadding(dpToPx(24), dpToPx(16), dpToPx(24), dpToPx(8)); textSize = 15f
        }
        val progress = android.widget.ProgressBar(this).apply {
            setPadding(dpToPx(24), 0, dpToPx(24), dpToPx(16))
        }
        val box = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            addView(msg); addView(progress)
        }
        val cancelled = java.util.concurrent.atomic.AtomicBoolean(false)
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Enrolling fingerprint")
            .setView(box)
            .setCancelable(false)
            .setNegativeButton("Cancel") { _, _ -> cancelled.set(true) }
            .create()
        dialog.show()

        if (usbBusy) { toast("Key is busy, try again in a moment"); dialog.dismiss(); return }
        usbBusy = true
        usbExecutor.execute {
            val conn = usbManager.openDevice(device)
            val wire = if (conn != null)
                com.token2.lkcompanion.fido.ctap.CtapHidWire.find(conn, device) else null
            if (conn == null || wire == null) {
                runOnUiThread { msg.text = "Couldn't open the key over USB."; }
                usbBusy = false
                return@execute
            }
            try {
                val client = com.token2.lkcompanion.fido.ctap.Ctap2Client(wire)
                val (session, first) = client.enrollBegin(pin)
                fun show(sample: com.token2.lkcompanion.fido.ctap.Ctap2Client.EnrollSample) {
                    runOnUiThread {
                        msg.text = client.sampleStatusText(sample.lastStatus) +
                            if (sample.remaining > 0) "\n\n${sample.remaining} more touch(es) needed."
                            else "\n\nDone!"
                    }
                }
                show(first)
                var sample = first
                while (!sample.complete && !cancelled.get()) {
                    sample = session.captureNext()
                    show(sample)
                }
                if (cancelled.get()) {
                    session.cancel()
                    runOnUiThread { dialog.dismiss(); toast("Enrollment cancelled") }
                } else {
                    val tid = session.templateId
                    runOnUiThread {
                        dialog.dismiss()
                        // Offer to name the new fingerprint.
                        val view = layoutInflater.inflate(R.layout.dialog_text_input, null)
                        val til = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilInput)
                        til.hint = "Fingerprint name (optional)"
                        val input = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etInput)
                        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                            .setTitle("Fingerprint enrolled")
                            .setMessage("Give it a name?")
                            .setView(view)
                            .setPositiveButton("Save") { _, _ ->
                                val name = input.text?.toString()?.trim().orEmpty()
                                if (name.isNotEmpty()) {
                                    fidoRepo.arm(FidoRepository.PendingOp.RenameFingerprint(pin, tid, name))
                                    showNfcOverlay("Hold your key to the phone", "Saving name…")
                                } else refreshFingerprintList(pin)
                            }
                            .setNegativeButton("Skip") { _, _ -> refreshFingerprintList(pin) }
                            .show()
                    }
                }
            } catch (e: com.token2.lkcompanion.fido.ctap.CtapError) {
                runOnUiThread { dialog.dismiss(); toast("Enroll failed: CTAP 0x${"%02X".format(e.code)}") }
            } catch (e: Exception) {
                runOnUiThread { dialog.dismiss(); toast("Enroll failed: ${e.message ?: "error"}") }
            } finally {
                wire.close(); conn.close(); usbBusy = false
            }
        }
    }

    private fun refreshFingerprintList(pin: String) {
        fidoRepo.arm(FidoRepository.PendingOp.ListFingerprints(pin))
        showNfcOverlay("Hold your key to the phone", "Refreshing fingerprints…")
    }

    // --- FIDO2 tab ---
    private fun showPane(m: Mode) {
        paneInfo.visibility = if (m == Mode.INFO) View.VISIBLE else View.GONE
        paneTotp.visibility = if (m == Mode.TOTP) View.VISIBLE else View.GONE
        paneFido.visibility = if (m == Mode.FIDO) View.VISIBLE else View.GONE
    }

    private fun runFidoTap(transport: SmartCardTransport) {
        Thread {
            val result = fidoRepo.executeOn(transport)
            handleFidoResult(result)
        }.start()
    }

    /** Blocking FIDO2-over-USB read via CTAPHID. Runs on the usbExecutor thread. */
    private fun fidoOverHidBlocking(device: UsbDevice) {
        runOnUiThread { fidoArmedHint.text = "Working over USB…" }
        val conn = usbManager.openDevice(device)
            ?: throw IllegalStateException("openDevice returned null")
        val wire = com.token2.lkcompanion.fido.ctap.CtapHidWire.find(conn, device)
        if (wire == null) {
            runOnUiThread { fidoArmedHint.text = "No FIDO (CTAPHID) interface on this USB device." }
            conn.close(); return
        }
        try {
            val result = fidoRepo.executeOnWire(wire)
            handleFidoResult(result)
        } catch (e: Exception) {
            // Never fail silently — surface the transport error.
            runOnUiThread {
                hideNfcOverlay()
                fidoArmedHint.text = "USB FIDO error: ${e.message ?: e.javaClass.simpleName}"
            }
        } finally {
            wire.close(); conn.close()
        }
    }

    private fun handleFidoResult(result: FidoRepository.OpResult) {
        runOnUiThread {
            hideNfcOverlay()
            // If the PIN was a one-shot (user didn't choose to keep it), forget it
            // now that the operation (incl. its post-op refresh) has completed.
            if (pendingForgetPin) { fidoRepo.forgetPin(); pendingForgetPin = false }
            when (result) {
                is FidoRepository.OpResult.Info -> {
                    renderFidoCard(result.info, result.pinRetries)
                    fidoArmedHint.text = result.message ?: ""
                }
                is FidoRepository.OpResult.Passkeys -> {
                    passkeyAdapter.submit(result.list)
                    val summary = result.message?.let { "$it ${result.list.size} passkey(s)." }
                        ?: "${result.list.size} passkey(s)."
                    if (passkeyScreenOpen) {
                        passkeyHint.text = if (result.list.isEmpty())
                            "No passkeys on this key." else summary
                    } else fidoArmedHint.text = summary
                }
                is FidoRepository.OpResult.Fingerprints -> {
                    fpAdapter.submit(result.list)
                    val summary = result.message?.let { "$it ${result.list.size} fingerprint(s)." }
                        ?: "${result.list.size} fingerprint(s)."
                    if (fpScreenOpen) {
                        fpHint.text = if (result.list.isEmpty())
                            "No fingerprints enrolled. Tap “Add fingerprint”." else summary
                    } else fidoArmedHint.text = summary
                }
                is FidoRepository.OpResult.Success -> {
                    fidoArmedHint.text = result.message
                    toast(result.message)
                    // If the user was in the passkey screen, drop back to the FIDO card.
                    if (passkeyScreenOpen) {
                        passkeyAdapter.submit(emptyList())
                        closePasskeyScreen()
                    }
                }
                is FidoRepository.OpResult.Failure -> {
                    if (passkeyScreenOpen) passkeyHint.text = "Failed: ${result.message}"
                    else fidoArmedHint.text = "Failed: ${result.message}"
                }
                FidoRepository.OpResult.NotFido2 ->
                    fidoArmedHint.text = "No FIDO2 applet on this key."
            }
        }
    }

    /** Apply the alphanumeric switch to a field's inputType (keeps it a password). */
    private fun setAlphaMode(field: com.google.android.material.textfield.TextInputEditText, alpha: Boolean) {
        // numberPassword = 0x12 (TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD)
        // textPassword   = 0x81 (TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD)
        field.inputType = if (alpha) 0x81 else 0x12
        field.setSelection(field.text?.length ?: 0)
    }

    /** PIN button: set (if none) or change (if set). */
    private fun promptPin() {
        val pinAlreadySet = fidoRepo.lastInfo?.clientPinSet == true
        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        val tilOld = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilOld)
        val tilNew = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilNew)
        val tilConfirm = view.findViewById<com.google.android.material.textfield.TextInputLayout>(R.id.tilConfirm)
        val oldField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinOld)
        val newField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinNew)
        val confirmField = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinConfirm)
        val switchAlpha = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchAlpha)
        val switchRemember = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchRemember)

        // Field set + labels depend on whether a PIN already exists.
        if (pinAlreadySet) {
            tilOld.visibility = View.VISIBLE
            tilOld.hint = "Current PIN"
            tilNew.hint = "New PIN"
            tilConfirm.hint = "Confirm new PIN"
        } else {
            tilOld.visibility = View.GONE
            tilNew.hint = "PIN"
            tilConfirm.hint = "Confirm PIN"
        }

        switchAlpha.setOnCheckedChangeListener { _, checked ->
            setAlphaMode(oldField, checked); setAlphaMode(newField, checked); setAlphaMode(confirmField, checked)
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(if (pinAlreadySet) "Change PIN" else "Set PIN")
            .setView(view)
            .setPositiveButton("Apply") { _, _ ->
                val oldPin = oldField.text?.toString() ?: ""
                val newPin = newField.text?.toString() ?: ""
                val confirmPin = confirmField.text?.toString() ?: ""
                if (newPin.length < 4) { toast("PIN must be at least 4 characters"); return@setPositiveButton }
                if (newPin != confirmPin) { toast("PINs don't match — try again"); return@setPositiveButton }
                if (switchRemember.isChecked) fidoRepo.rememberPin(newPin)
                if (!pinAlreadySet) {
                    fidoRepo.arm(FidoRepository.PendingOp.SetPin(newPin))
                    showNfcOverlay("Hold your key to the phone", "Setting PIN…")
                } else {
                    if (oldPin.isBlank()) { toast("Enter your current PIN"); return@setPositiveButton }
                    fidoRepo.arm(FidoRepository.PendingOp.ChangePin(oldPin, newPin))
                    showNfcOverlay("Hold your key to the phone", "Changing PIN…")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * Collect a single PIN for an operation. If one is already remembered this
     * session, skip the prompt and use it directly.
     */
    private fun promptSinglePin(
        title: String, message: String,
        pageScopedPin: Boolean = false,
        onCancel: (() -> Unit)? = null,
        onPin: (String) -> Unit,
    ) {
        fidoRepo.rememberedPin?.let { onPin(it); return }

        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        // Single-PIN: hide the "current PIN" and "confirm" fields, reuse the "PIN" field.
        view.findViewById<View>(R.id.tilOld).visibility = View.GONE
        view.findViewById<View>(R.id.tilConfirm).visibility = View.GONE
        val field = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinNew)
        val switchAlpha = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchAlpha)
        val switchRemember = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchRemember)
        switchAlpha.setOnCheckedChangeListener { _, checked -> setAlphaMode(field, checked) }
        if (pageScopedPin) {
            // The fingerprint screen manages its own PIN scope: remembered on entry,
            // dropped on exit — the session-wide "remember" choice isn't offered here.
            view.findViewById<View>(R.id.rememberRow).visibility = View.GONE
            view.findViewById<View>(R.id.rememberNotice).visibility = View.GONE
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(title)
            .setMessage(message)
            .setView(view)
            .setPositiveButton("OK") { _, _ ->
                val pin = field.text?.toString() ?: ""
                if (pin.isBlank()) toast("Enter the PIN")
                else {
                    // Remember for the rest of this operation so any follow-up read
                    // (e.g. the post-op refresh) doesn't prompt again. If the user
                    // didn't opt to keep it, forget it once the operation settles.
                    val keep = switchRemember.isChecked || pageScopedPin
                    fidoRepo.rememberPin(pin)
                    if (!keep) pendingForgetPin = true
                    onPin(pin)
                }
            }
            .setNegativeButton("Cancel") { _, _ -> onCancel?.invoke() }
            .show()
    }

    /** Set when a one-shot PIN was used; cleared after the operation's result lands. */
    private var pendingForgetPin = false

    /**
     * On-screen USB diagnostics — enumerate the connected device's interfaces and
     * endpoints, and report what the CTAPHID interface probe sees. Lets us debug
     * devices like Pico-FIDO without a logcat connection.
     */
    private fun showUsbDiagnostics() {
        val device = connectedUsbDevice ?: run {
            toast("No USB device connected"); return
        }
        usbExecutor.execute {
            val sb = StringBuilder()
            sb.append("vid=%04X pid=%04X\n".format(device.vendorId, device.productId))
            sb.append("interfaces=${device.interfaceCount}\n\n")
            val hidClass = android.hardware.usb.UsbConstants.USB_CLASS_HID
            val ccidClass = UsbCcidTransport.USB_CLASS_CCID
            for (i in 0 until device.interfaceCount) {
                val iface = device.getInterface(i)
                val clsName = when (iface.interfaceClass) {
                    hidClass -> "HID"; ccidClass -> "CCID"; else -> "cls${iface.interfaceClass}"
                }
                sb.append("if[$i] id=${iface.id} $clsName eps=${iface.endpointCount}\n")
                for (e in 0 until iface.endpointCount) {
                    val ep = iface.getEndpoint(e)
                    val dir = if (ep.direction == android.hardware.usb.UsbConstants.USB_DIR_IN) "IN" else "OUT"
                    val type = when (ep.type) {
                        android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_INT -> "INT"
                        android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_BULK -> "BULK"
                        else -> "t${ep.type}"
                    }
                    sb.append("   ep $dir $type max=${ep.maxPacketSize}\n")
                }
            }
            sb.append("\n-- FIDO probe --\n")
            try {
                val conn = usbManager.openDevice(device)
                if (conn == null) sb.append("openDevice: null\n")
                else {
                    sb.append(com.token2.lkcompanion.fido.ctap.CtapHidWire.findDiagnostic(conn, device))
                    conn.close()
                }
            } catch (e: Exception) {
                sb.append("probe error: ${e.message}\n")
            }
            val report = sb.toString()
            runOnUiThread {
                val tv = android.widget.TextView(this).apply {
                    text = report; setPadding(40, 30, 40, 30)
                    setTextIsSelectable(true)
                    typeface = android.graphics.Typeface.MONOSPACE
                    textSize = 11f
                }
                val scroll = android.widget.ScrollView(this).apply { addView(tv) }
                com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                    .setTitle("USB diagnostics")
                    .setView(scroll)
                    .setPositiveButton("Copy") { _, _ ->
                        val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("usb-diag", report))
                        toast("Copied")
                    }
                    .setNegativeButton("Close", null)
                    .show()
            }
        }
    }

    private fun toast(msg: String) =
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show()

    /** Details popup for one passkey: rp, user, algorithm, credProtect, credential id. */
    private fun showPasskeyInfo(pk: com.token2.lkcompanion.fido.ctap.Ctap2Client.Passkey) {
        fun algoName(a: Int?): String = when (a) {
            null -> "—"
            -7 -> "ES256 (ECDSA P-256)"
            -8 -> "EdDSA (Ed25519)"
            -35 -> "ES384 (ECDSA P-384)"
            -36 -> "ES512 (ECDSA P-521)"
            -257 -> "RS256 (RSA)"
            else -> "alg $a"
        }
        fun credProtectName(c: Int?): String = when (c) {
            1 -> "Optional (uvOptional)"
            2 -> "Optional with credential ID (uvOptionalWithCredentialIDList)"
            3 -> "Required (uvRequired)"
            null -> "—"
            else -> "level $c"
        }
        val rows = listOf(
            "Relying party" to pk.rpId,
            "User name" to (pk.userName ?: "—"),
            "Display name" to (pk.userDisplayName ?: "—"),
            "User handle" to (pk.userHandleHex?.let { if (it.length > 32) it.take(32) + "…" else it } ?: "—"),
            "Algorithm" to algoName(pk.algorithm),
            "Credential protection" to credProtectName(pk.credProtect),
            "Credential ID" to (pk.credentialIdB64.let { if (it.length > 28) it.take(28) + "…" else it }),
        )
        // Build a clean two-column-ish layout via a vertical LinearLayout.
        val ctx = this
        val ll = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(dpToPx(24), dpToPx(8), dpToPx(24), dpToPx(8))
        }
        for ((label, value) in rows) {
            val lbl = android.widget.TextView(ctx).apply {
                text = label; textSize = 12f; alpha = 0.6f
                setPadding(0, dpToPx(8), 0, 0)
            }
            val v = android.widget.TextView(ctx).apply {
                text = value; textSize = 15f; setTextIsSelectable(true)
            }
            ll.addView(lbl); ll.addView(v)
        }
        val scroll = android.widget.ScrollView(ctx).apply { addView(ll) }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(pk.userDisplayName ?: pk.userName ?: pk.rpId)
            .setView(scroll)
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy credential ID") { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("credential-id", pk.credentialIdB64))
                toast("Credential ID copied")
            }
            .show()
    }

    private fun dpToPx(dp: Int): Int = (dp * resources.displayMetrics.density).toInt()

    private fun confirmDeletePasskey(pk: com.token2.lkcompanion.fido.ctap.Ctap2Client.Passkey) {
        // Confirm the destructive action first, then collect/reuse the PIN.
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Delete passkey?")
            .setMessage("Remove \"${pk.userDisplayName ?: pk.userName ?: pk.rpId}\" " +
                "from ${pk.rpId}? This can't be undone.")
            .setPositiveButton("Delete") { _, _ ->
                promptSinglePin("Confirm with PIN",
                    "Enter the key's PIN to delete this passkey.") { pin ->
                    fidoRepo.arm(FidoRepository.PendingOp.DeletePasskey(pin, pk.credentialId))
                    showNfcOverlay("Hold your key to the phone", "Deleting passkey…")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (fpScreenOpen) { closeFingerprintScreen(); return }
        if (passkeyScreenOpen) { closePasskeyScreen(); return }
        @Suppress("DEPRECATION") super.onBackPressed()
    }

    // --- options menu ---
    override fun onCreateOptionsMenu(menu: android.view.Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: android.view.MenuItem): Boolean = when (item.itemId) {
        R.id.menu_refresh -> {
            // Clear the current view first so stale data doesn't linger while we
            // re-read from scratch.
            when (mode) {
                Mode.INFO -> {
                    infoStatusCard.renderHint("Reading key from scratch…")
                    showNfcOverlay("Hold your key to the phone", "Reading key overview…")
                }
                Mode.TOTP -> {
                    if (!armOtpRefresh()) {
                        toast("Finish or cancel the current OTP operation before refreshing.")
                    } else {
                        adapter.submit(emptyList())
                        oathAdapter.submit(emptyList())
                        armedHint.text = "Reading OTP from scratch…"
                        showNfcOverlay("Hold your key to the phone", "Reading OTP entries…")
                    }
                }
                Mode.FIDO -> {
                    fidoStatusCard.renderHint("Reading FIDO2 from scratch…")
                    fidoArmedHint.text = ""
                    passkeyAdapter.submit(emptyList())
                    fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
                    showNfcOverlay("Hold your key to the phone", "Reading FIDO2 status…")
                }
            }
            true
        }
        R.id.menu_forget_pin -> {
            fidoRepo.forgetPin()
            val hadOtp = rememberedOtpPin != null
            rememberedOtpPin = null
            repo.clearPin()
            toast(if (hadOtp) "Remembered PINs cleared (FIDO2 + OTP)" else "Remembered PIN cleared")
            true
        }
        R.id.menu_interfaces -> {
            // HID-HOTP config is USB-only here: require a key plugged into the
            // phone's USB-C port. Don't show the NFC "present your key" overlay.
            val usbDev = connectedUsbDevice
            if (usbDev == null) {
                toast("Plug the Token2 key into USB to change HID-HOTP.")
            } else {
                if (mode != Mode.TOTP) goToTab(Mode.TOTP, R.id.nav_totp)
                repo.arm(Token2Repository.PendingOp.ReadConfig)
                // Drive the read over the already-connected USB device directly.
                rereadUsbForCurrentTab()
            }
            true
        }
        R.id.menu_yk_apps -> {
            // Read the YubiKey's application config on the next tap, then show the
            // toggle dialog. Runs regardless of tab (managementPending gates it).
            managementRepo.arm(
                com.token2.lkcompanion.management.ManagementRepository.PendingOp.ReadInfo
            )
            managementPending = true
            showNfcOverlay("Hold your key to the phone", "Reading YubiKey applications…")
            rereadUsbForCurrentTab()   // drive it now if already on USB
            true
        }
        R.id.menu_otp_pin -> {
            // Read OTP-PIN status on the next tap (CCID/NFC), then offer
            // set/verify/change/remove. pinPending gates the one-shot dispatch.
            armPin(
                com.token2.lkcompanion.token2ui.Token2PinRepository.PendingOp.Status,
                "Reading OTP PIN status…",
            )
            true
        }
        R.id.menu_usb_diag -> {
            showUsbDiagnostics()
            true
        }
        R.id.menu_about -> {
            showAboutDialog()
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun post(text: String) = runOnUiThread { otpStatusCard.renderHint(text) }

    /** Friendly label for an MDS certification status string. */
    private fun certLabel(status: String?): String = when (status) {
        null -> "Not in metadata"
        "FIDO_CERTIFIED" -> "FIDO Certified"
        "FIDO_CERTIFIED_L1" -> "FIDO Certified L1"
        "FIDO_CERTIFIED_L1plus" -> "FIDO Certified L1+"
        "FIDO_CERTIFIED_L2" -> "FIDO Certified L2"
        "FIDO_CERTIFIED_L2plus" -> "FIDO Certified L2+"
        "FIDO_CERTIFIED_L3" -> "FIDO Certified L3"
        "FIDO_CERTIFIED_L3plus" -> "FIDO Certified L3+"
        "NOT_FIDO_CERTIFIED" -> "Not FIDO certified"
        else -> status.replace("_", " ")
    }

    /** About dialog: app description, credits, and FIDO MDS status + update. */
    private fun showAboutDialog() {
        val version = try { "v" + packageManager.getPackageInfo(packageName, 0).versionName }
            catch (_: Exception) { "" }
        val body = "Libre Key Companion is an open source, manufacturer agnostic, " +
            "FIDO management tool provided by Token2 Sàrl and the contributors.\n\n" +
            "Authenticator names and certification levels are matched against the " +
            "FIDO Alliance Metadata Service (MDS).\n\n" +
            "Metadata source: ${mds.sourceLabel} (${mds.entryCount} authenticators)."
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Libre Key Companion $version")
            .setMessage(body)
            .setPositiveButton("Close", null)
            .setNeutralButton("Update metadata") { _, _ -> updateMdsFromFido() }
            .show()
    }

    /** Fetch the FIDO Alliance MDS3 BLOB and refresh the local metadata cache. */
    private fun updateMdsFromFido() {
        toast("Downloading FIDO metadata…")
        Thread {
            try {
                val url = java.net.URL("https://mds3.fidoalliance.org/")
                val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                    connectTimeout = 15000; readTimeout = 30000
                    requestMethod = "GET"
                }
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                val n = mds.saveFetched(text)
                runOnUiThread {
                    if (n > 0) toast("Metadata updated: $n authenticators")
                    else toast("Couldn't parse metadata")
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Update failed: ${e.message ?: "network error"}") }
            }
        }.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { unregisterReceiver(usbReceiver) }
        runCatching { unregisterReceiver(usbDetachReceiver) }
        runCatching { unregisterReceiver(usbAttachReceiver) }
        runCatching { usbExecutor.shutdownNow() }
    }
}
