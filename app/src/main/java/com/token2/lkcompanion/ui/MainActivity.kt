package com.token2.lkcompanion.ui

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.openpgp.OpenPgpApplet
import com.token2.lkcompanion.piv.PivApplet
import com.token2.lkcompanion.token2.Token2HidTransport
import com.token2.lkcompanion.token2ui.AddEntryDialog
import com.token2.lkcompanion.token2ui.Token2EntryAdapter
import com.token2.lkcompanion.oathui.OathEntryAdapter
import com.token2.lkcompanion.token2ui.Token2Repository
import com.token2.lkcompanion.transport.NfcTransport
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
    /** Which OTP applet the current key uses, decided at read time. */
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
    /** Serializes all USB reads so two taps/resumes can't race on one connection. */
    private val usbExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
    /** Guard so a replug (attach intent + resume) doesn't open the same device twice. */
    @Volatile private var usbBusy = false

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
            repo.arm(Token2Repository.PendingOp.Refresh)
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
        )
        findViewById<android.widget.ImageButton>(R.id.btnRefresh).setOnClickListener {
            repo.arm(Token2Repository.PendingOp.Refresh)
            showNfcOverlay("Hold your key to the phone", "Reading OTP entries…")
        }
        findViewById<android.widget.ImageButton>(R.id.btnAdd).setOnClickListener {
            AddEntryDialog.show(
                context = this,
                onScanRequested = { handle ->
                    pendingScanHandle = handle
                    val opts = com.journeyapps.barcodescanner.ScanOptions().apply {
                        setDesiredBarcodeFormats(
                            com.journeyapps.barcodescanner.ScanOptions.QR_CODE)
                        setPrompt("Scan a TOTP QR code")
                        setBeepEnabled(false)
                        setOrientationLocked(true)   // follow the app's portrait UI
                    }
                    qrLauncher.launch(opts)
                },
                onReady = { entry ->
                    if (otpIsOath) {
                        // Convert the parsed entry to an OATH credential and arm OATH add.
                        val cred = entryToOathCredential(entry)
                        oathRepo.arm(com.token2.lkcompanion.oathui.OathRepository.PendingOp.Add(cred))
                        showNfcOverlay("Hold your key to the phone", "Writing ${entry.accountName}…")
                        return@show
                    }
                    val cachedDup = repo.cachedDuplicateOf(entry)
                    if (cachedDup != null) {
                        // Advisory: cache suggests this identity already exists.
                        android.app.AlertDialog.Builder(this)
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
                    } else {
                        repo.arm(Token2Repository.PendingOp.Add(entry))
                        showNfcOverlay("Hold your key to the phone",
                            "Writing ${entry.accountName}…")
                    }
                },
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
            if (mode == Mode.TOTP) repo.arm(Token2Repository.PendingOp.Refresh)
            if (mode == Mode.FIDO) fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
            rereadUsbForCurrentTab()
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
        WindowCompat.getInsetsController(window, window.decorView)
            .isAppearanceLightStatusBars = false
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

    /** 1s ticker drives the TOTP countdown on already-fetched codes. */
    private fun startTotpTicker() {
        val handler = android.os.Handler(mainLooper)
        val r = object : Runnable {
            override fun run() {
                val secs = com.token2.lkcompanion.oath.OathCore
                    .secondsRemaining(System.currentTimeMillis() / 1000, 30)
                if (otpIsOath) oathAdapter.tick(secs) else adapter.tick(secs)
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

    /** Set briefly after a detach to debounce the resume-scan permission prompt. */
    @Volatile private var suppressScanUntil = 0L

    /**
     * Wipe all on-screen data that belongs to a now-absent key, so stale values
     * (OTP codes, FIDO status, passkeys) don't linger. Called on USB detach.
     */
    private fun clearKeyData(reason: String) {
        // Clear cached state in the repositories too, so a later read starts fresh.
        repo.arm(Token2Repository.PendingOp.Refresh)
        fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
        fidoRepo.forgetPin()
        runOnUiThread {
            adapter.submit(emptyList())
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
                if (mode == Mode.INFO) readInfoOverlay(transport, device)
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
        when (mode) {
            Mode.FIDO -> { runFidoTap(transport); return }
            Mode.INFO -> { Thread { try { readInfoOverlay(transport) } finally { transport.close() } }.start(); return }
            Mode.TOTP -> Thread { try { readToken2(transport) } finally { transport.close() } }.start()
        }
    }

    /** Blocking Token2 OTP read + UI update. Caller owns transport lifecycle. */
    private fun readToken2(transport: SmartCardTransport) {
        val result = repo.executeOn(transport)
        // If this isn't a Token2 key, try the standard OATH applet (Pico/YubiKey).
        if (result is Token2Repository.OpResult.NotAToken2Key) {
            readOath(transport); return
        }
        otpIsOath = false
        runOnUiThread {
            if (otpList.adapter !== adapter) otpList.adapter = adapter
            hideNfcOverlay()
            when (result) {
                is Token2Repository.OpResult.Success -> {
                    adapter.submit(result.entries)
                    armedHint.text = "${result.message}. ${result.entries.size} entr" +
                        if (result.entries.size == 1) "y." else "ies."
                }
                is Token2Repository.OpResult.DuplicateExists -> {
                    adapter.submit(result.entries)
                    android.app.AlertDialog.Builder(this)
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
                Token2Repository.OpResult.NotAToken2Key -> { /* handled above */ }
            }
        }
    }

    /** OTP read via the standard OATH applet. Swaps the OTP list to the OATH adapter. */
    private fun readOath(transport: SmartCardTransport) {
        val result = oathRepo.executeOn(transport)
        otpIsOath = true
        runOnUiThread {
            if (otpList.adapter !== oathAdapter) otpList.adapter = oathAdapter
            hideNfcOverlay()
            when (result) {
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.Success -> {
                    oathAdapter.submit(result.entries)
                    armedHint.text = "${result.message}. ${result.entries.size} entr" +
                        if (result.entries.size == 1) "y." else "ies."
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.DuplicateExists -> {
                    oathAdapter.submit(result.entries)
                    android.app.AlertDialog.Builder(this)
                        .setTitle("Entry already exists")
                        .setMessage("\"${result.existingLabel}\" is already on the key. Overwrite it?")
                        .setPositiveButton("Overwrite") { _, _ ->
                            oathRepo.arm(com.token2.lkcompanion.oathui.OathRepository.PendingOp.Add(
                                result.cred, allowOverwrite = true))
                            showNfcOverlay("Hold your key to the phone", "Replacing ${result.cred.account}…")
                        }
                        .setNegativeButton("Cancel") { _, _ ->
                            oathRepo.arm(com.token2.lkcompanion.oathui.OathRepository.PendingOp.Refresh)
                            armedHint.text = "Add cancelled — entry already exists."
                        }
                        .show()
                }
                is com.token2.lkcompanion.oathui.OathRepository.OpResult.Failure ->
                    armedHint.text = "Failed: ${result.message}"
                com.token2.lkcompanion.oathui.OathRepository.OpResult.NotAnOathKey ->
                    armedHint.text = "No OTP applet (Token2 or OATH) on this key."
            }
        }
    }

    /** Convert a parsed Token2 entry to an OATH credential (TOTP). */
    private fun entryToOathCredential(e: com.token2.lkcompanion.token2.Token2Codec.Entry):
            com.token2.lkcompanion.oath.OathCredential {
        val algo = when (e.algorithm) {
            com.token2.lkcompanion.token2.Token2Codec.ALG_SHA256 -> com.token2.lkcompanion.oath.OathCore.HashAlgo.SHA256
            else -> com.token2.lkcompanion.oath.OathCore.HashAlgo.SHA1
        }
        return com.token2.lkcompanion.oath.OathCredential(
            issuer = e.appName.ifBlank { null },
            account = e.accountName,
            secret = e.seed ?: ByteArray(0),
            type = com.token2.lkcompanion.oath.OathCredential.Type.TOTP,
            algo = algo,
            digits = e.codeLength,
            period = if (e.timestep > 0) e.timestep else 30,
        )
    }

    private fun confirmDeleteOath(d: com.token2.lkcompanion.oathui.OathRepository.Display) {
        android.app.AlertDialog.Builder(this)
            .setTitle("Delete entry?")
            .setMessage("Remove \"${if (d.issuer.isBlank()) d.account else d.issuer + " / " + d.account}\" " +
                "from the key permanently?")
            .setPositiveButton("Delete") { _, _ ->
                oathRepo.arm(com.token2.lkcompanion.oathui.OathRepository.PendingOp.Delete(d.name))
                showNfcOverlay("Hold your key to the phone", "Deleting ${d.account}…")
            }
            .setNegativeButton("Cancel", null)
            .show()
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

    /** OATH applet row for the Info overview — taps through to the OTP tab. */
    private fun oathInfoRow(transport: SmartCardTransport): StatusCard.Row = try {
        val a = OathApplet(transport); val info = a.select()
        val n = a.list().size
        StatusCard.Row(R.drawable.ic_timer, "OATH OTP", "$n credential(s) · tap to manage",
            chipText = "Present", chipState = StatusCard.State.SUCCESS,
            onClick = { goToTab(Mode.TOTP, R.id.nav_totp) })
    } catch (e: Exception) {
        StatusCard.Row(R.drawable.ic_timer, "OATH OTP", "not on this key",
            chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
    }

    /** Token2 OTP row for the Info overview — taps through to the OTP tab. */
    private fun token2InfoRow(transport: SmartCardTransport): StatusCard.Row = try {
        val c = com.token2.lkcompanion.token2.Token2Client.overNfc(transport)
        val n = try {
            c.enumerate(System.currentTimeMillis() / 1000).size
        } catch (e: com.token2.lkcompanion.token2.Token2Exception.EntryNotFound) { 0 }
        StatusCard.Row(R.drawable.ic_timer, "On-device OTP", "$n entry(s) · tap to manage",
            chipText = "Present", chipState = StatusCard.State.SUCCESS,
            onClick = { goToTab(Mode.TOTP, R.id.nav_totp) })
    } catch (e: Exception) {
        val msg = e.message ?: ""
        if (listOf("6A82", "6A86", "6D00", "6999").any { msg.contains(it) })
            StatusCard.Row(R.drawable.ic_timer, "On-device OTP", "not on this key",
                chipText = "—", chipState = StatusCard.State.NEUTRAL, dimmed = true)
        else
            StatusCard.Row(R.drawable.ic_timer, "On-device OTP", "error",
                chipText = "Error", chipState = StatusCard.State.DANGER)
    }

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
            if (m == Mode.TOTP) repo.arm(Token2Repository.PendingOp.Refresh)
            if (m == Mode.FIDO) fidoRepo.arm(FidoRepository.PendingOp.ReadInfo)
            rereadUsbForCurrentTab()
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
        android.app.AlertDialog.Builder(this)
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
        promptSinglePin("Load passkeys", "Enter the key's PIN to list passkeys.") { pin ->
            fidoRepo.arm(FidoRepository.PendingOp.ListPasskeys(pin))
            showNfcOverlay("Hold your key to the phone", "Reading passkeys…")
        }
    }

    private fun closePasskeyScreen() {
        passkeyScreenOpen = false
        panePasskeys.visibility = View.GONE
    }

    // --- fingerprints screen ---
    private fun openFingerprintScreen() {
        fpScreenOpen = true
        paneFingerprints.visibility = View.VISIBLE
        fpAdapter.submit(fidoRepo.cachedFingerprints)
        fpHint.text = if (fidoRepo.cachedFingerprints.isEmpty())
            "Tap your key to load fingerprints." else "Tap your key to refresh."
        promptSinglePin("Load fingerprints", "Enter the key's PIN to list fingerprints.") { pin ->
            fidoRepo.rememberPin(pin)   // held for the enroll session too
            fidoRepo.arm(FidoRepository.PendingOp.ListFingerprints(pin))
            showNfcOverlay("Hold your key to the phone", "Reading fingerprints…")
        }
    }

    private fun closeFingerprintScreen() {
        fpScreenOpen = false
        paneFingerprints.visibility = View.GONE
    }

    private fun promptRenameFingerprint(fp: com.token2.lkcompanion.fido.ctap.Ctap2Client.Fingerprint) {
        val input = com.google.android.material.textfield.TextInputEditText(this).apply {
            setText(fp.name ?: ""); hint = "Fingerprint name"
        }
        val til = com.google.android.material.textfield.TextInputLayout(this).apply {
            setPadding(dpToPx(24), dpToPx(8), dpToPx(24), 0); addView(input)
        }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle("Rename fingerprint")
            .setView(til)
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
                        val input = com.google.android.material.textfield.TextInputEditText(this).apply {
                            hint = "Fingerprint name (optional)"
                        }
                        val til = com.google.android.material.textfield.TextInputLayout(this).apply {
                            setPadding(dpToPx(24), dpToPx(8), dpToPx(24), 0); addView(input)
                        }
                        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                            .setTitle("Fingerprint enrolled")
                            .setMessage("Give it a name?")
                            .setView(til)
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
                is FidoRepository.OpResult.Success ->
                    fidoArmedHint.text = result.message
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
    private fun promptSinglePin(title: String, message: String, onPin: (String) -> Unit) {
        fidoRepo.rememberedPin?.let { onPin(it); return }

        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        // Single-PIN: hide the "current PIN" and "confirm" fields, reuse the "PIN" field.
        view.findViewById<View>(R.id.tilOld).visibility = View.GONE
        view.findViewById<View>(R.id.tilConfirm).visibility = View.GONE
        val field = view.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.pinNew)
        val switchAlpha = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchAlpha)
        val switchRemember = view.findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.switchRemember)
        switchAlpha.setOnCheckedChangeListener { _, checked -> setAlphaMode(field, checked) }

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
                    val keep = switchRemember.isChecked
                    fidoRepo.rememberPin(pin)
                    if (!keep) pendingForgetPin = true
                    onPin(pin)
                }
            }
            .setNegativeButton("Cancel", null)
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
                android.app.AlertDialog.Builder(this)
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
                    adapter.submit(emptyList())
                    armedHint.text = "Reading OTP from scratch…"
                    repo.arm(Token2Repository.PendingOp.Refresh)
                    showNfcOverlay("Hold your key to the phone", "Reading OTP entries…")
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
            toast("Remembered PIN cleared")
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
        runCatching { usbExecutor.shutdownNow() }
    }
}
