#!/usr/bin/env python3
"""
Generate the bundled MDS JSON (res/raw/mds_bundled.json) for Libre Key Companion.

Output format: a flat JSON array (the app's native shape, also used by the
in-app "Update metadata" cache) — no special packaging:

    [ {"aaguid": "...", "description": "...", "status": "...", "icon": "data:image/png;base64,..."}, ... ]

Processing pipeline:
  * --hardware-only (default): drop software/platform authenticators
    (keyProtection="software" with no "hardware") — pass --include-software to keep them.
  * Icons are normalized: SVG data-URIs are rendered to transparent PNG via resvg_py,
    and every icon is downscaled so its longest edge is <= 96 px (smaller icons stay).
  * Entries are sorted by attestation root CA so the same vendor's records are
    adjacent — identical icon payloads then sit inside DEFLATE's 32 KB window and
    the APK build compresses the duplicates away for free.

Usage:
    python generate_mds_bundle.py                # full hardware set, processed icons
    python generate_mds_bundle.py --no-icons     # names + certification only (small)
    python generate_mds_bundle.py --filter yubi token2 feitian   # name whitelist
    python generate_mds_bundle.py --out app/src/main/res/raw/mds_bundled.json

Notes:
  * The BLOB is public and needs no token.
  * The BLOB's JWT signature is NOT verified — display data only; do not use it
    for attestation trust decisions.
  * Dependencies for icon processing: Pillow (always) and resvg_py (only when the
    blob contains SVG icons). Both ship Windows wheels.
"""
import argparse, base64, hashlib, io, json, os, re, sys

MDS_URL = "https://mds3.fidoalliance.org/"
MAX_PX = 96


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def fetch_blob(url: str) -> str:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "lkc-mds-bundler"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8")


def decode_jwt_payload(jwt: str) -> dict:
    parts = jwt.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT (expected header.payload.signature)")
    return json.loads(b64url_decode(parts[1]))


def best_certification(entry: dict):
    """Most recent FIDO_CERTIFIED* status. MDS3 lists statusReports newest-first
    (e.g. [FIDO_CERTIFIED_L1, FIDO_CERTIFIED]) — first match wins."""
    for report in entry.get("statusReports", []):
        status = report.get("status", "")
        if status.startswith("FIDO_CERTIFIED"):
            return status
    return None


def render_svg(svg_text: str, max_px: int):
    """Render an SVG document to transparent PNG bytes via resvg_py, normalizing
    the root size first: some MDS SVGs use pt units (resvg rejects them) and some
    lack width/height entirely (only a viewBox)."""
    import resvg_py
    svg_text = re.sub(r'(<svg\b[^>]*?)\s+width="[^"]*"', r"\1", svg_text, count=1)
    svg_text = re.sub(r'(<svg\b[^>]*?)\s+height="[^"]*"', r"\1", svg_text, count=1)
    m = re.search(r'viewBox\s*=\s*"([\d.\s+-]+)"', svg_text, re.I)
    vw = vh = None
    if m:
        parts = m.group(1).split()
        if len(parts) == 4:
            vw, vh = float(parts[2]), float(parts[3])
    if vw and vh:
        s = max_px / max(vw, vh, 1)
        svg_text = svg_text.replace(
            "<svg", '<svg width="%d" height="%d" ' % (max(1, round(vw * s)), max(1, round(vh * s))), 1)
    else:
        svg_text = svg_text.replace("<svg", '<svg width="%d" height="%d" ' % (max_px, max_px), 1)
    out = resvg_py.svg_to_bytes(svg_string=svg_text)
    if isinstance(out, list):
        out = bytes(out)
    return out


def process_icon(uri: str, max_px: int):
    """Minimal-touch icon normalization. Only two transformations are ever applied:
    SVG data-URIs are rendered to PNG, and icons larger than max_px are downscaled.
    An icon that already fits (a small PNG) is returned byte-for-byte as shipped by
    the vendor — it is never re-encoded."""
    from PIL import Image
    payload = uri.split(",", 1)[1]
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
    if uri.startswith("data:image/svg"):
        raw = render_svg(raw.decode("utf-8", "ignore"), max_px)
        img = Image.open(io.BytesIO(raw))
        w, h = img.size
        scale = min(1.0, max_px / max(w, h))
        if scale < 1.0:
            img = img.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)
        out = io.BytesIO()
        img.convert("RGBA").save(out, "PNG", optimize=True)
        return out.getvalue()
    img = Image.open(io.BytesIO(raw))
    w, h = img.size
    if max(w, h) <= max_px:
        return raw                                    # already fits — keep as-is
    img = img.convert("RGBA")
    scale = max_px / max(w, h)
    img = img.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def build(blob: dict, keep_icons: bool, name_filters, include_software: bool):
    out = []
    for entry in blob.get("entries", []):
        ms = entry.get("metadataStatement") or {}
        aaguid = entry.get("aaguid") or ms.get("aaguid")
        if not aaguid:
            continue  # skip U2F-only / AAID entries (no AAGUID)
        name = ms.get("description", "Unknown authenticator")
        if name_filters and not any(f.lower() in name.lower() for f in name_filters):
            continue
        if not include_software:
            kp = ms.get("keyProtection") or []
            if "software" in kp and "hardware" not in kp:
                continue  # software/platform authenticator (passkey provider etc.)
        rec = {"aaguid": aaguid, "description": name}
        cert = best_certification(entry)
        if cert:
            rec["status"] = cert
        icon = ms.get("icon")
        if keep_icons and icon:
            try:
                png = process_icon(icon, MAX_PX)
                rec["icon"] = "data:image/png;base64," + base64.b64encode(png).decode()
            except Exception as ex:
                print(f"  ! icon skipped for {name[:44]}: {ex}", file=sys.stderr)
        ca_key = hashlib.md5("|".join(
            sorted(ms.get("attestationRootCertificates") or [])).encode()).hexdigest()[:8] \
            if ms.get("attestationRootCertificates") else "zzz" + aaguid
        out.append((ca_key, rec))
    # Same vendor adjacent: identical icon payloads inside the DEFLATE window.
    out.sort(key=lambda t: (t[0], t[1]["aaguid"]))
    return [rec for _, rec in out]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="mds_bundled.json")
    ap.add_argument("--no-icons", action="store_true", help="omit icon data URIs")
    ap.add_argument("--filter", nargs="*", default=None,
                    help="only keep authenticators whose name contains any of these")
    ap.add_argument("--include-software", action="store_true",
                    help="keep software/platform authenticators (default: dropped)")
    ap.add_argument("--from-file", default=None,
                    help="read a previously-downloaded BLOB (JWT) from a file instead of the network")
    args = ap.parse_args()

    print("Fetching MDS BLOB…", file=sys.stderr)
    jwt = open(args.from_file).read() if args.from_file else fetch_blob(MDS_URL)
    blob = decode_jwt_payload(jwt)
    print(f"  BLOB no={blob.get('no')} nextUpdate={blob.get('nextUpdate')} "
          f"entries={len(blob.get('entries', []))}", file=sys.stderr)

    entries = build(blob, keep_icons=not args.no_icons,
                    name_filters=args.filter, include_software=args.include_software)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, separators=(",", ":"))
    kb = os.path.getsize(args.out) / 1024
    print(f"Wrote {len(entries)} authenticators to {args.out} ({kb:.0f} KB)", file=sys.stderr)


if __name__ == "__main__":
    main()
