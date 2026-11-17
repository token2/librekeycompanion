package com.token2.lkcompanion.token2ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R
import com.token2.lkcompanion.token2.Token2Codec

/**
 * Renders Token2 on-device OTP entries. TOTP codes the device returned are shown
 * with a countdown over the entry's own timestep, and only while they are still
 * current (see [token2EntryUiState]); HOTP / button-required entries show a
 * placeholder (their code is only available via an explicit read + button touch).
 */
class Token2EntryAdapter(
    private val onDelete: (Token2Codec.Entry) -> Unit,
    private val onCopy: (Token2Codec.Entry) -> Unit,
    // Tapped a button-required entry (its code is only revealable over USB with a
    // physical touch). The activity decides what to do based on the transport.
    private val onRevealButtonEntry: (Token2Codec.Entry) -> Unit = {},
    // Tapped a TOTP entry whose code has expired: read the key again.
    private val onRefresh: () -> Unit = {},
) : RecyclerView.Adapter<Token2EntryAdapter.VH>() {

    private var entries: List<Token2Codec.Entry> = emptyList()
    private var unixSeconds: Long = System.currentTimeMillis() / 1000

    fun submit(list: List<Token2Codec.Entry>) {
        entries = list
        unixSeconds = System.currentTimeMillis() / 1000
        notifyDataSetChanged()
    }

    /** Replace a (button-required) entry with the revealed version carrying its code. */
    fun revealCode(target: Token2Codec.Entry, revealed: Token2Codec.Entry) {
        val idx = entries.indexOfFirst {
            it.appName == target.appName && it.accountName == target.accountName
        }
        if (idx >= 0) {
            entries = entries.toMutableList().also { it[idx] = revealed }
            notifyItemChanged(idx)
        }
    }

    /** Called by a 1s ticker so countdowns move and expired codes drop out between taps. */
    fun tick(nowUnixSeconds: Long) {
        unixSeconds = nowUnixSeconds
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_otp_entry, parent, false)
        return VH(v)
    }

    override fun getItemCount() = entries.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = entries[position]
        holder.title.text = if (e.appName.isBlank()) e.accountName else e.appName
        holder.subtitle.text = e.accountName
        val state = token2EntryUiState(e, unixSeconds)
        val code = e.otpCode
        // An expired code read without the button can simply be read again. One that
        // needed the button falls back to its placeholder: it takes another touch.
        val refreshOnTap = state.expired && !e.buttonRequired
        when {
            code != null && state.showCode -> {
                holder.code.text = spaceCode(code)
                holder.meta.text = if (e.isTotp) {
                    "TOTP • ${e.timestep}s • ${state.secondsLeft}s left"
                } else {
                    "HOTP"
                }
            }
            refreshOnTap -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "TOTP • expired • tap row to refresh"
            }
            !e.isTotp -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "HOTP • tap: needs USB + button touch"
            }
            else -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "Button-protected • tap: needs USB + touch"
            }
        }
        holder.delete.setOnClickListener { onDelete(e) }
        // Copy is only meaningful while there is a current code to copy.
        holder.copy.visibility = if (state.showCode) View.VISIBLE else View.GONE
        holder.copy.setOnClickListener { onCopy(e) }
        when {
            state.showCode -> {
                holder.itemView.setOnClickListener(null)
                holder.itemView.isClickable = false
            }
            refreshOnTap -> holder.itemView.setOnClickListener { onRefresh() }
            // A button-required entry has no code yet; tapping the row explains how
            // to reveal it (USB + touch), instead of doing nothing.
            else -> holder.itemView.setOnClickListener { onRevealButtonEntry(e) }
        }
    }

    private fun spaceCode(code: String): String =
        if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}"
        else if (code.length == 8) "${code.substring(0, 4)} ${code.substring(4)}"
        else code

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val title: TextView = v.findViewById(R.id.entryTitle)
        val subtitle: TextView = v.findViewById(R.id.entrySubtitle)
        val code: TextView = v.findViewById(R.id.entryCode)
        val meta: TextView = v.findViewById(R.id.entryMeta)
        val copy: ImageButton = v.findViewById(R.id.entryCopy)
        val delete: ImageButton = v.findViewById(R.id.entryDelete)
    }
}
