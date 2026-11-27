package com.token2.lkcompanion.transport

/** ISO 7816-3 Answer-To-Reset helpers. */
object Atr {

    /**
     * The historical bytes of [atr]: the K bytes (T0's low nibble) after the
     * interface bytes that T0 and each TDi announce. Empty when the card sent
     * none; null when [atr] is too short for what it announces.
     */
    fun historicalBytes(atr: ByteArray): ByteArray? {
        if (atr.size < 2) return null
        val t0 = atr[1].toInt() and 0xFF
        val count = t0 and 0x0F
        var present = t0 ushr 4          // which of TAi, TBi, TCi, TDi follow
        var i = 2
        while (true) {
            if (present and 0x1 != 0) i++
            if (present and 0x2 != 0) i++
            if (present and 0x4 != 0) i++
            if (present and 0x8 == 0) break
            if (i >= atr.size) return null
            present = (atr[i].toInt() and 0xFF) ushr 4
            i++
        }
        if (i + count > atr.size) return null
        return atr.copyOfRange(i, i + count)
    }
}
