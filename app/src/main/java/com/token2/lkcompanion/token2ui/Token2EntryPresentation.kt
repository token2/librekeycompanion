package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.oath.OathCore
import com.token2.lkcompanion.token2.Token2Codec

internal data class Token2EntryUiState(
    /** The code may be shown and copied. */
    val showCode: Boolean,
    /** A TOTP code was read, but the window it belongs to is over. */
    val expired: Boolean,
    /** Seconds left in the entry's own window; 0 unless a TOTP code is shown. */
    val secondsLeft: Int,
)

/**
 * What a Token2 row may show at [nowUnixSeconds].
 *
 * The key computes a TOTP code for the timestamp sent with the read, so a code
 * is current only while "now" is still in the same window as that timestamp,
 * counted in the entry's own timestep. The app cannot produce the next code
 * itself (the seed never leaves the key); once the window is over the code has
 * to go, and the key has to be read again.
 *
 * HOTP codes do not expire with time. A TOTP code with no read time is left
 * showing rather than hidden on a guess.
 */
internal fun token2EntryUiState(
    entry: Token2Codec.Entry,
    nowUnixSeconds: Long,
): Token2EntryUiState {
    if (entry.otpCode == null) return Token2EntryUiState(false, false, 0)
    if (!entry.isTotp || entry.timestep <= 0) return Token2EntryUiState(true, false, 0)

    val period = entry.timestep
    val readAt = entry.readAtSeconds
    val current = readAt == null || readAt / period == nowUnixSeconds / period
    return if (current) {
        Token2EntryUiState(true, false, OathCore.secondsRemaining(nowUnixSeconds, period))
    } else {
        Token2EntryUiState(false, true, 0)
    }
}
