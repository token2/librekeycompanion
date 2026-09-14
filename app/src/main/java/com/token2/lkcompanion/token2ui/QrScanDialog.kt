package com.token2.lkcompanion.token2ui

import android.app.Dialog
import android.content.Context
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.TextView
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.fragment.app.DialogFragment
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.token2.lkcompanion.R
import java.util.EnumMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Full-screen, in-process QR scanner (issue #23).
 *
 * Why not the zxing-android-embedded CaptureActivity:
 *  - it is a *separate activity*, declared `sensorLandscape` in the library
 *    manifest, so it appeared rotated 90° against the app's portrait UI and
 *    invited the user to rotate the phone — which then re-created MainActivity
 *    (and with it destroyed the "Add OTP entry" dialog) on return;
 *  - being a separate activity it also let the OS drop MainActivity under
 *    camera memory pressure, with the same "pop-up closed by itself" symptom;
 *  - it drives the deprecated Camera1 API with one-shot autofocus every ~2 s,
 *    which hunts badly on modern phones.
 *
 * This DialogFragment keeps the host activity in the foreground, uses CameraX
 * (continuous autofocus by default, rotation handled by [PreviewView]) and
 * decodes frames with the ZXing core [MultiFormatReader]. Tap-to-focus and a
 * torch toggle are provided for hard cases. The result is delivered on the
 * main thread through [Listener] on the host activity, exactly once.
 */
class QrScanDialog : DialogFragment() {

    /** Implemented by the host activity; called on the main thread. */
    interface Listener {
        fun onQrScanned(text: String)
        fun onQrScanCancelled() {}
    }

    private var camera: Camera? = null
    private var executor: ExecutorService? = null
    private var delivered = false
    private val reader = MultiFormatReader().apply {
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java)
        hints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
        hints[DecodeHintType.TRY_HARDER] = true
        setHints(hints)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setStyle(STYLE_NO_FRAME, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog =
        super.onCreateDialog(savedInstanceState).apply {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
        }

    override fun onCreateView(
        inflater: android.view.LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        val ctx = requireContext()
        val root = FrameLayout(ctx).apply { setBackgroundColor(Color.BLACK) }

        val preview = PreviewView(ctx).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
        root.addView(preview)

        // Viewfinder frame.
        root.addView(View(ctx).apply {
            val side = (260 * resources.displayMetrics.density).toInt()
            layoutParams = FrameLayout.LayoutParams(side, side, Gravity.CENTER)
            background = android.graphics.drawable.GradientDrawable().apply {
                setStroke((2 * resources.displayMetrics.density).toInt(), Color.WHITE)
                cornerRadius = 16 * resources.displayMetrics.density
                setColor(Color.TRANSPARENT)
            }
        })

        root.addView(TextView(ctx).apply {
            text = getString(R.string.otp_scan_qr_prompt)
            setTextColor(Color.WHITE)
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(32, 48, 32, 0)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP)
        })

        val pad = (16 * resources.displayMetrics.density).toInt()
        root.addView(ImageButton(ctx).apply {
            setImageResource(R.drawable.ic_back)
            setColorFilter(Color.WHITE)
            background = null
            contentDescription = getString(android.R.string.cancel)
            setPadding(pad, pad, pad, pad)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP or Gravity.START)
            setOnClickListener { dismissAllowingStateLoss() }
        })

        var torchOn = false
        root.addView(TextView(ctx).apply {
            text = getString(R.string.otp_scan_torch)
            setTextColor(Color.WHITE)
            setPadding(pad * 2, pad, pad * 2, pad)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL).apply { bottomMargin = pad * 3 }
            setOnClickListener {
                val cam = camera ?: return@setOnClickListener
                if (cam.cameraInfo.hasFlashUnit()) {
                    torchOn = !torchOn
                    cam.cameraControl.enableTorch(torchOn)
                }
            }
        })

        // Tap-to-focus: many phones only lock focus on the subject after an
        // explicit metering request even in continuous-AF mode.
        preview.setOnTouchListener { v, ev ->
            if (ev.action == android.view.MotionEvent.ACTION_UP) {
                v.performClick()
                val cam = camera ?: return@setOnTouchListener true
                val point = preview.meteringPointFactory.createPoint(ev.x, ev.y)
                val action = FocusMeteringAction.Builder(point, FocusMeteringAction.FLAG_AF)
                    .setAutoCancelDuration(3, TimeUnit.SECONDS)
                    .build()
                cam.cameraControl.startFocusAndMetering(action)
            }
            true
        }

        startCamera(ctx, preview)
        return root
    }

    private fun startCamera(ctx: Context, previewView: PreviewView) {
        val future = ProcessCameraProvider.getInstance(ctx)
        future.addListener({
            val provider = try { future.get() } catch (e: Exception) {
                dismissAllowingStateLoss(); return@addListener
            }
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            val analysisExecutor = Executors.newSingleThreadExecutor().also { executor = it }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setResolutionSelector(
                    ResolutionSelector.Builder()
                        .setResolutionStrategy(
                            ResolutionStrategy(
                                android.util.Size(1280, 720),
                                ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                            )
                        )
                        .build()
                )
                .build()
            analysis.setAnalyzer(analysisExecutor) { image -> analyze(image) }
            try {
                provider.unbindAll()
                camera = provider.bindToLifecycle(
                    viewLifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                dismissAllowingStateLoss()
            }
        }, ContextCompat.getMainExecutor(ctx))
    }

    /**
     * Decode the Y (luminance) plane straight from the YUV_420_888 buffer. No
     * rotation is applied — QR finder patterns are orientation-independent, so
     * the code is found whichever way the sensor or phone is turned.
     */
    private fun analyze(image: ImageProxy) {
        if (delivered) { image.close(); return }
        try {
            val plane = image.planes[0]
            val buf = plane.buffer
            val rowStride = plane.rowStride
            val width = image.width
            val height = image.height
            val bytes = ByteArray(buf.remaining())
            buf.get(bytes)
            val source = PlanarYUVLuminanceSource(
                bytes, rowStride, height, 0, 0, width, height, false)
            val text = try {
                reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
            } catch (e: NotFoundException) {
                // Also try the inverted image — some vendors print light-on-dark QRs.
                try {
                    reader.decodeWithState(BinaryBitmap(HybridBinarizer(source.invert()))).text
                } catch (e2: NotFoundException) { null }
            } finally {
                reader.reset()
            }
            if (text != null && !delivered) {
                delivered = true
                view?.post { deliver(text) }
            }
        } catch (_: Exception) {
            // Malformed frame; wait for the next one.
        } finally {
            image.close()
        }
    }

    private fun deliver(text: String) {
        (activity as? Listener)?.onQrScanned(text)
        dismissAllowingStateLoss()
    }

    override fun onDismiss(dialog: android.content.DialogInterface) {
        super.onDismiss(dialog)
        if (!delivered) (activity as? Listener)?.onQrScanCancelled()
    }

    override fun onDestroyView() {
        executor?.shutdown()
        executor = null
        camera = null
        super.onDestroyView()
    }

    companion object {
        const val TAG = "QrScanDialog"
    }
}
