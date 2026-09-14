package com.token2.lkcompanion.fido

import android.content.Context
import org.json.JSONObject
import org.json.JSONArray
import java.io.File

/**
 * FIDO Metadata Service (MDS) lookup. Maps an authenticator's AAGUID to a friendly
 * name, certification level, and (optionally) an icon.
 *
 * Two data sources, tried in order:
 *  1. A user-updated cache file (downloaded from the FIDO Alliance MDS3 endpoint and
 *     stored in the app's files dir).
 *  2. A bundled starter set (res/raw/mds_bundled.json) so lookups work offline out
 *     of the box.
 *
 * The FIDO MDS3 BLOB is a JWT; the middle segment is base64url-encoded JSON with an
 * `entries` array, each having `aaguid`, `metadataStatement` (name=`description`,
 * `icon`), and `statusReports` (certification `status`). We parse that shape when a
 * fetched BLOB is provided, and a simpler {aaguid: {...}} shape for the bundled file.
 */
class MdsRepository(private val appContext: Context) {

    data class Entry(
        val aaguid: String,
        val name: String,
        val certification: String?,   // e.g. FIDO_CERTIFIED_L1
        val iconDataUri: String?,     // data:image/png;base64,... if present
    )

    private var map: Map<String, Entry> = emptyMap()
    @Volatile var sourceLabel: String = "none"
        private set
    @Volatile var entryCount: Int = 0
        private set

    private val cacheFile get() = File(appContext.filesDir, "mds_cache.json")

    /** Load the best available source into memory. Call once (e.g. on first use). */
    fun load() {
        // Prefer a fetched/cached BLOB-derived JSON; fall back to the bundled set.
        val fromCache = runCatching {
            if (cacheFile.exists()) parseAny(cacheFile.readText(), "cache") else null
        }.getOrNull()
        if (fromCache != null && fromCache.isNotEmpty()) {
            map = fromCache; sourceLabel = "downloaded"; entryCount = map.size; return
        }
        val bundled = runCatching {
            val res = appContext.resources
            val id = res.getIdentifier("mds_bundled", "raw", appContext.packageName)
            var text = res.openRawResource(id).bufferedReader().use { it.readText() }.trim()
            // Accept whatever shape was dropped in: the flat array [{aaguid,...}],
            // a raw JWT BLOB, the official MDS3 {no,nextUpdate,entries:[...]} JSON, or
            // the simple {entries:{aaguid:{}}} map.
            if (!text.startsWith("{") && !text.startsWith("[") && text.count { it == '.' } >= 2)
                text = decodeJwtClaims(text)
            parseAny(text, "bundled")
        }.getOrDefault(emptyMap())
        map = bundled; sourceLabel = "bundled"; entryCount = map.size
    }

    /** Look up an authenticator by AAGUID (hex, with or without dashes). */
    fun lookup(aaguidHex: String?): Entry? {
        if (aaguidHex.isNullOrBlank()) return null
        return map[normalize(aaguidHex)]
    }

    /**
     * Save a freshly-fetched MDS payload (either a raw JWT BLOB or already-decoded
     * JSON) to the cache and reload. Returns the number of entries parsed.
     */
    fun saveFetched(payload: String): Int {
        val t = payload.trimStart()
        // Only treat as a JWT if it isn't already JSON (JSON starts with { or [).
        val json = if (!t.startsWith("{") && !t.startsWith("[") && t.count { it == '.' } >= 2) {
            decodeJwtClaims(payload)        // raw JWT BLOB — decode the claims segment
        } else payload
        val parsed = parseAny(json, "downloaded")
        if (parsed.isNotEmpty()) {
            // Persist a normalized {aaguid:{...}} JSON for fast reloads.
            cacheFile.writeText(toBundledJson(parsed))
            map = parsed; sourceLabel = "downloaded"; entryCount = map.size
        }
        return parsed.size
    }

    // ---- parsing ----

    private fun parseAny(text: String, label: String): Map<String, Entry> {
        val trimmed = text.trimStart()
        // Flat array format: [ {aaguid, description, icon, status, ...}, ... ]
        if (trimmed.startsWith("[")) return parseFlatArray(JSONArray(text))
        val obj = JSONObject(text)
        return if (obj.has("entries") && obj.optJSONArray("entries") != null)
            parseBlob(obj)              // official MDS3 BLOB shape (entries is an array)
        else parseBundled(text)         // simple {entries:{aaguid:{...}}} shape
    }

    /**
     * Parse the flat-array shape: a JSON array of authenticator objects, each with
     * `aaguid`, `description` (name), `icon` (data URI), and `status` (certification).
     * This is the format used by the bundled mds_bundled.json.
     */
    private fun parseFlatArray(arr: JSONArray): Map<String, Entry> {
        val out = HashMap<String, Entry>()
        for (i in 0 until arr.length()) {
            val e = arr.optJSONObject(i) ?: continue
            val aaguid = e.optString("aaguid", null) ?: continue
            out[normalize(aaguid)] = Entry(
                normalize(aaguid),
                e.optString("description", "Unknown authenticator"),
                e.optString("status", null),
                e.optString("icon", null),
            )
        }
        return out
    }

    /** Parse the official MDS3 BLOB JSON ({no, nextUpdate, entries:[...]}) . */
    private fun parseBlob(obj: JSONObject): Map<String, Entry> {
        val out = HashMap<String, Entry>()
        val arr = obj.getJSONArray("entries")
        for (i in 0 until arr.length()) {
            val e = arr.optJSONObject(i) ?: continue
            val ms = e.optJSONObject("metadataStatement") ?: continue
            val aaguid = (e.optString("aaguid", null) ?: ms.optString("aaguid", null)) ?: continue
            val name = ms.optString("description", "Unknown authenticator")
            val icon = ms.optString("icon", null)
            // Most-recent certification from statusReports. MDS3 lists reports
            // newest-first (e.g. [FIDO_CERTIFIED_L1, FIDO_CERTIFIED]), so the
            // first FIDO_CERTIFIED* entry is the current level.
            var cert: String? = null
            val reports = e.optJSONArray("statusReports")
            if (reports != null) {
                for (r in 0 until reports.length()) {
                    val status = reports.optJSONObject(r)?.optString("status") ?: continue
                    if (status.startsWith("FIDO_CERTIFIED")) { cert = status; break }
                }
            }
            out[normalize(aaguid)] = Entry(normalize(aaguid), name, cert, icon)
        }
        return out
    }

    /** Parse the bundled {entries:{aaguid:{name,certification,icon}}} shape. */
    private fun parseBundled(text: String): Map<String, Entry> {
        val obj = JSONObject(text)
        val entries = obj.optJSONObject("entries") ?: return emptyMap()
        val out = HashMap<String, Entry>()
        val keys = entries.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = entries.optJSONObject(k) ?: continue
            out[normalize(k)] = Entry(
                normalize(k),
                v.optString("name", "Unknown authenticator"),
                v.optString("certification", null),
                v.optString("icon", null),
            )
        }
        return out
    }

    /** Serialize entries in the same flat-array format used by the bundled file:
     *  [ {aaguid, description, icon, status}, ... ]. Keeps the in-app update and the
     *  bundled asset in one consistent shape. */
    private fun toBundledJson(m: Map<String, Entry>): String {
        val arr = JSONArray()
        for ((_, e) in m) {
            arr.put(JSONObject().apply {
                put("aaguid", e.aaguid)
                put("description", e.name)
                e.iconDataUri?.let { put("icon", it) }
                e.certification?.let { put("status", it) }
            })
        }
        return arr.toString()
    }

    private fun decodeJwtClaims(jwt: String): String {
        val parts = jwt.trim().split(".")
        require(parts.size >= 2) { "Not a JWT" }
        val payload = parts[1]
        val bytes = android.util.Base64.decode(
            payload, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
        return String(bytes, Charsets.UTF_8)
    }

    private fun normalize(aaguid: String): String =
        aaguid.lowercase().replace("-", "").trim()

    companion object {
        /**
         * Decode an MDS icon (a `data:image/...;base64,...` URI) into a Bitmap.
         * Returns null if absent or unparseable.
         */
        fun decodeIcon(dataUri: String?): android.graphics.Bitmap? {
            if (dataUri.isNullOrBlank()) return null
            val comma = dataUri.indexOf(',')
            if (comma < 0 || !dataUri.substring(0, comma).contains("base64")) return null
            return try {
                val b = android.util.Base64.decode(
                    dataUri.substring(comma + 1), android.util.Base64.DEFAULT)
                android.graphics.BitmapFactory.decodeByteArray(b, 0, b.size)
            } catch (_: Exception) { null }
        }
    }
}
