"""Draw the 'bytes sent by the server' chart from a results JSON, as light and dark SVGs.

Standard library only, so the chart can be regenerated wherever the benchmark runs:
    python -m pqtls.plot results/windows-openssl-3.5.6.json docs/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

SIGS = [
    ("ecdsa-p256", "ECDSA P-256"),
    ("ed25519", "Ed25519"),
    ("rsa-2048", "RSA-2048"),
    ("mldsa44", "ML-DSA-44"),
    ("mldsa65", "ML-DSA-65"),
    ("mldsa87", "ML-DSA-87"),
]
GROUPS = [("X25519", "X25519"), ("X25519MLKEM768", "X25519MLKEM768")]

# Categorical slots 1-3 of the reference palette, validated for adjacent-pair CVD separation
# on GitHub's light (#ffffff) and dark (#0d1117) surfaces; "other" is a neutral, not a series.
THEMES = {
    "light": dict(surface="#ffffff", text="#1f2328", muted="#59636e", grid="#d1d9e0",
                  series=("#2a78d6", "#eb6834", "#1baf7a"), other="#b6bcc3"),
    "dark": dict(surface="#0d1117", text="#f0f6fc", muted="#9198a1", grid="#3d444d",
                 series=("#3987e5", "#d95926", "#199e70"), other="#5c636b"),
}
SEGMENTS = ("ServerHello (key share)", "Certificate", "CertificateVerify", "Other framing")

W, LEFT, RIGHT = 760, 190, 70
BAR, ROW, GROUP_GAP, TOP = 14, 19, 12, 92
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif"


def segments(result: dict) -> list[int]:
    hs = result["handshake"]
    rec = hs["received"]
    parts = [rec.get("ServerHello", 0), rec.get("Certificate", 0), rec.get("CertificateVerify", 0)]
    return parts + [max(hs["bytes_read"] - sum(parts), 0)]


def svg(results: dict[tuple[str, str], dict], theme: str) -> str:
    t = THEMES[theme]
    colors = (*t["series"], t["other"])
    totals = [r["handshake"]["bytes_read"] for r in results.values()]
    xmax = 14000 if max(totals) <= 14000 else (max(totals) // 2000 + 1) * 2000
    plot_w = W - LEFT - RIGHT
    sx = plot_w / xmax
    rows_h = len(SIGS) * (len(GROUPS) * ROW + GROUP_GAP)
    height = TOP + rows_h + 34
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" '
        f'viewBox="0 0 {W} {height}" font-family="{FONT}" role="img" '
        f'aria-label="Bytes sent by the server during a TLS 1.3 handshake, by signature algorithm and key exchange">',
        f'<rect width="{W}" height="{height}" fill="{t["surface"]}"/>',
        f'<text x="20" y="30" font-size="16" font-weight="600" fill="{t["text"]}">'
        f'Bytes the server sends to complete a TLS 1.3 handshake</text>',
        f'<text x="20" y="50" font-size="12" fill="{t["muted"]}">'
        f'Self-signed leaf certificate, OpenSSL 3.5. Totals at the end of each bar.</text>',
    ]
    # Legend
    lx = 20
    for name, color in zip(SEGMENTS, colors):
        out.append(f'<rect x="{lx}" y="64" width="10" height="10" rx="2" fill="{color}"/>')
        out.append(f'<text x="{lx + 15}" y="73" font-size="12" fill="{t["text"]}">{escape(name)}</text>')
        lx += 15 + 7 * len(name) + 22
    # Grid and axis
    axis_y = TOP + rows_h
    for v in range(0, xmax + 1, 2000):
        x = LEFT + v * sx
        out.append(f'<line x1="{x:.1f}" y1="{TOP - 6}" x2="{x:.1f}" y2="{axis_y}" '
                   f'stroke="{t["grid"]}" stroke-width="1"/>')
        label = "0" if v == 0 else f"{v // 1000}k"
        out.append(f'<text x="{x:.1f}" y="{axis_y + 16}" font-size="11" fill="{t["muted"]}" '
                   f'text-anchor="middle">{label}</text>')
    out.append(f'<text x="{LEFT + plot_w}" y="{axis_y + 30}" font-size="11" fill="{t["muted"]}" '
               f'text-anchor="end">bytes</text>')
    # Bars
    y = TOP
    for sig, sig_label in SIGS:
        out.append(f'<text x="20" y="{y + ROW - 4}" font-size="13" font-weight="600" '
                   f'fill="{t["text"]}">{escape(sig_label)}</text>')
        for group, group_label in GROUPS:
            r = results[(sig, group)]
            out.append(f'<text x="{LEFT - 8}" y="{y + BAR - 2}" font-size="11" fill="{t["muted"]}" '
                       f'text-anchor="end">{escape(group_label)}</text>')
            x = LEFT
            parts = [p for p in segments(r)]
            for i, (value, color) in enumerate(zip(parts, colors)):
                w = value * sx
                if w <= 0:
                    continue
                gap = 2 if i < len(parts) - 1 else 0  # 2px surface gap between stacked fills
                draw_w = max(w - gap, 0.5)
                last = i == len(parts) - 1
                title = f"{sig_label}, {group_label}: {SEGMENTS[i]} {value} B"
                if last and draw_w > 4:
                    out.append(
                        f'<path d="M{x:.1f},{y} h{draw_w - 4:.1f} a4,4 0 0 1 4,4 v{BAR - 8} '
                        f'a4,4 0 0 1 -4,4 h-{draw_w - 4:.1f} z" fill="{color}">'
                        f'<title>{escape(title)}</title></path>')
                else:
                    out.append(f'<rect x="{x:.1f}" y="{y}" width="{draw_w:.1f}" height="{BAR}" '
                               f'fill="{color}"><title>{escape(title)}</title></rect>')
                x += w
            total = r["handshake"]["bytes_read"]
            out.append(f'<text x="{x + 6:.1f}" y="{y + BAR - 2}" font-size="11" '
                       f'fill="{t["text"]}">{total:,}</text>')
            y += ROW
        y += GROUP_GAP
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    src, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    data = json.loads(src.read_text(encoding="utf-8"))
    results = {(r["signature"], r["group"]): r for r in data["results"]}
    missing = [(s, g) for s, _ in SIGS for g, _ in GROUPS if (s, g) not in results]
    if missing:
        raise SystemExit(f"results file lacks {missing}")
    outdir.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        path = outdir / f"server-bytes-{theme}.svg"
        path.write_text(svg(results, theme), encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
