package com.token2.lkcompanion.ui

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.token2.lkcompanion.R

/**
 * Builds a scannable status card: a vertical stack of rows, each an icon + label
 * + optional secondary line + a colored state chip on the right. Replaces the old
 * cramped multi-line status text with something readable at a glance.
 *
 * Used by both the OTP and FIDO2 tabs. Rows are added programmatically because the
 * facts differ per tab and per key.
 */
class StatusCard(private val container: LinearLayout) {

    private val ctx: Context = container.context
    private val inflater = LayoutInflater.from(ctx)

    enum class State { SUCCESS, NEUTRAL, WARNING, DANGER }

    data class Row(
        val iconRes: Int,
        val label: String,
        val secondary: String? = null,
        val chipText: String? = null,
        val chipState: State = State.NEUTRAL,
        val onClick: (() -> Unit)? = null,
        /** Optional copy-to-clipboard value shown as a copy icon. */
        val copyValue: String? = null,
        val onCopy: ((String) -> Unit)? = null,
        /** Optional inline action button (e.g. "Set", "Change", "Toggle", "Manage"). */
        val actionText: String? = null,
        val onAction: (() -> Unit)? = null,
        /** Render dimmed/disabled (e.g. an applet that isn't present on this key). */
        val dimmed: Boolean = false,
        /** Optional bitmap icon (e.g. an MDS device logo); used instead of iconRes. */
        val iconBitmap: android.graphics.Bitmap? = null,
    )

    /** Replace the card's contents with these rows. */
    fun render(rows: List<Row>) {
        container.removeAllViews()
        rows.forEachIndexed { i, row ->
            if (i > 0) container.addView(inflater.inflate(R.layout.status_divider, container, false))
            container.addView(buildRow(row))
        }
    }

    /** Show a single full-width informational line (e.g. "Tap your key…"). */
    fun renderHint(text: String) {
        container.removeAllViews()
        val tv = TextView(ctx).apply {
            this.text = text
            textSize = 13f
            alpha = 0.7f
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }
        container.addView(tv)
    }

    private fun buildRow(row: Row): View {
        val v = inflater.inflate(R.layout.status_row, container, false)
        val iconView = v.findViewById<ImageView>(R.id.rowIcon)
        if (row.iconBitmap != null) iconView.setImageBitmap(row.iconBitmap)
        else iconView.setImageResource(row.iconRes)
        v.findViewById<TextView>(R.id.rowLabel).text = row.label
        val sec = v.findViewById<TextView>(R.id.rowSecondary)
        if (row.secondary != null) { sec.text = row.secondary; sec.visibility = View.VISIBLE }
        val chip = v.findViewById<TextView>(R.id.rowChip)
        if (row.chipText != null) {
            chip.text = row.chipText
            chip.visibility = View.VISIBLE
            applyChip(chip, row.chipState)
        }
        val copy = v.findViewById<android.widget.ImageButton>(R.id.rowCopy)
        if (row.copyValue != null && row.onCopy != null) {
            copy.visibility = View.VISIBLE
            copy.setOnClickListener { row.onCopy.invoke(row.copyValue) }
        }
        val action = v.findViewById<android.widget.Button>(R.id.rowAction)
        if (row.actionText != null && row.onAction != null) {
            action.text = row.actionText
            action.visibility = View.VISIBLE
            action.setOnClickListener { row.onAction.invoke() }
        }
        row.onClick?.let { cb -> v.setOnClickListener { cb() } }
        if (row.dimmed) v.alpha = 0.4f
        return v
    }

    private fun applyChip(chip: TextView, state: State) {
        val (bg, fg) = when (state) {
            State.SUCCESS -> R.drawable.chip_success to R.color.lkc_chip_success_fg
            State.WARNING -> R.drawable.chip_warning to R.color.lkc_chip_warning_fg
            State.DANGER  -> R.drawable.chip_danger to R.color.lkc_chip_danger_fg
            State.NEUTRAL -> R.drawable.chip_neutral to R.color.lkc_chip_neutral_fg
        }
        chip.setBackgroundResource(bg)
        chip.setTextColor(ContextCompat.getColor(ctx, fg))
    }

    private fun dp(v: Int): Int = (v * ctx.resources.displayMetrics.density).toInt()
}
