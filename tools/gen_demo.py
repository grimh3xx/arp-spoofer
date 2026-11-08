#!/usr/bin/env python3
"""Render the animated terminal demo for arp-spoofer into docs/demo.svg.

Filmstrip model (same as the pe-binaries / daclseek demos): each frame is a
full screen snapshot stacked vertically, stepped by a CSS keyframe animation.
Font embedding (JBM) is reused from the sibling github-profile brand toolchain.

Usage: python3 tools/gen_demo.py [--static N]
"""
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

BRAND = Path.home() / "github-profile" / "scripts"
sys.path.insert(0, str(BRAND))
try:
    from brand import finish  # type: ignore
except Exception:
    def finish(svg, faces=None):
        return svg

MONO = "'JBM','JetBrains Mono',ui-monospace,Consolas,Menlo,monospace"

C = {
    "user": "#22D3EE", "punct": "#D5DDE8", "path": "#60A5FA", "cmd": "#F1F5FB",
    "text": "#C5CFDD", "muted": "#8B98AD", "cyan": "#22D3EE",
    "red": "#F87171", "amber": "#FBBF24", "green": "#34D399", "white": "#F1F5FB",
}

CW = 8.4
FS = 14
LH = 23
Y0 = 18
VIEW_W, VIEW_H = 874, 576
MAXLINES = (VIEW_H - Y0) // LH
W, H = 910, 652
TYPE, OUT, PAUSE, HOLD = 1, 2, 7, 44


def seg(t, color="text", bold=False):
    return (t, color, bold)


def prompt():
    return [seg("grimh3xx@centraltech", "user"), seg(":", "punct"),
            seg("~/arp-spoofer", "path"), seg("$ ", "punct")]


class Session:
    def __init__(self):
        self.history, self.active, self.frames, self.durs = [], None, [], []

    def _snap(self, dur):
        lines = [l[:] for l in self.history]
        if self.active is not None:
            lines.append(self.active[:])
        self.frames.append(lines)
        self.durs.append(dur)

    def type(self, text):
        self.active = prompt() + [seg("", "cmd")]
        for ch in text:
            s = self.active[-1]
            self.active[-1] = seg(s[0] + ch, "cmd")
            self._snap(TYPE)
        self._snap(PAUSE)

    def enter(self):
        if self.active is not None:
            self.history.append(self.active)
            self.active = None

    def out(self, line, dur=OUT):
        self.history.append(line if isinstance(line, list) else [seg(line)])
        self._snap(dur)

    def blank(self):
        self.out([seg("")], dur=1)

    def cursor_hold(self):
        self.active = prompt() + [seg("█", "cyan")]
        self._snap(HOLD)


def build():
    s = Session()
    s.out([seg("arp-spoofer", "cyan", True), seg(" — authorised use only", "muted")], dur=1)
    s.blank()

    s.type("sudo ./arp-spoofer scan -i eth0")
    s.enter()
    s.out([seg("scanning ", "text"), seg("192.168.1.0/24", "white"), seg(" on eth0 (254 hosts)...", "text")])
    s.out([seg("IP                MAC", "muted")])
    s.out([seg("-" * 36, "muted")], dur=1)
    s.out([seg("192.168.1.1       ", "white"), seg("a4:2b:0e:91:3c:10", "text"), seg("  (gateway)", "muted")])
    s.out([seg("192.168.1.23      ", "white"), seg("5c:cf:7f:22:0a:e1", "text")])
    s.out([seg("192.168.1.50      ", "white"), seg("00:0c:29:7a:1b:04", "text")])
    s.out([seg("3 host(s) up.", "green", True)])
    s.blank()

    s.type("sudo ./arp-spoofer arp -i eth0 -t 192.168.1.23 -g 192.168.1.1")
    s.enter()
    s.out([seg("resolving MAC addresses...", "text")])
    s.out([seg("  target  192.168.1.23 -> 5c:cf:7f:22:0a:e1", "text")])
    s.out([seg("  gateway 192.168.1.1  -> a4:2b:0e:91:3c:10", "text")])
    s.out([seg("poisoning every 2s — Ctrl+C to stop and restore...", "amber")])
    s.out([seg("  sent 7 poison round(s)", "text")])
    s.out([seg("^C", "muted")], dur=PAUSE)
    s.out([seg("restoring ARP caches...", "text")])
    s.out([seg("done — LAN restored.", "green", True)])
    s.blank()

    s.type("sudo ./arp-spoofer respond -i eth0")
    s.enter()
    s.out([seg("responder on eth0 as 192.168.1.50 — mode: poison (active)", "text")])
    s.out([seg("[LLMNR] ", "cyan", True), seg("192.168.1.23:54912 asked for ", "text"), seg("\"wpad\"", "white", True)])
    s.out([seg("        -> answered with 192.168.1.50", "green")])
    s.out([seg("[NBT-NS] ", "cyan", True), seg("192.168.1.23:137 asked for ", "text"), seg("\"FILESRV\"", "white", True)])
    s.out([seg("        -> answered with 192.168.1.50", "green")])
    s.cursor_hold()
    return s


def render_rows(frames):
    out = []
    for n, lines in enumerate(frames):
        window = lines[-MAXLINES:] if len(lines) > MAXLINES else lines
        parts = [f'<g id="r{n}">']
        for j, line in enumerate(window):
            y = Y0 + j * LH
            x = 0.0
            for text, color, bold in line:
                if text:
                    wt = ' font-weight="700"' if bold else ""
                    tl = len(text) * CW
                    parts.append(
                        f'<text x="{x:.1f}" y="{y}" fill="{C[color]}"{wt} '
                        f'textLength="{tl:.1f}" lengthAdjust="spacingAndGlyphs">'
                        f'{escape(text)}</text>')
                x += len(text) * CW
        parts.append("</g>")
        out.append("".join(parts))
    return "".join(out)


def keyframes(durs):
    total = sum(durs)
    cum, stops = 0, []
    for i, d in enumerate(durs):
        stops.append(f"{cum / total * 100:.3f}%{{transform:translateY(-{i * VIEW_H}px)}}")
        cum += d
    stops.append(f"100%{{transform:translateY(-{(len(durs) - 1) * VIEW_H}px)}}")
    dur_s = max(10, round(total * 0.09))
    return ("@keyframes play{" + "".join(stops) + "}"
            f".strip{{animation:play {dur_s}s steps(1,end) infinite}}"
            "@media(prefers-reduced-motion){.strip{animation:none;"
            f"transform:translateY(-{(len(durs) - 1) * VIEW_H}px)}}}}")


def render(static_frame=None):
    s = build()
    rows = render_rows(s.frames)
    nframes = len(s.frames)
    strip_items = "".join(
        f'<g transform="translate(0,{i * VIEW_H})"><use href="#r{i}"/></g>'
        for i in range(nframes))
    if static_frame is None:
        css = keyframes(s.durs)
        strip_open = '<g class="strip" '
    else:
        f = min(static_frame, nframes - 1)
        css = ""
        strip_open = f'<g transform="translate(0,{-f * VIEW_H})" '
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" aria-label="arp-spoofer demo">'
        f'<style>{css}</style><defs>{rows}</defs>'
        f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="12" fill="#111826" stroke="#1E2A3D"/>'
        f'<path d="M0 40H{W}" stroke="#1E2A3D"/>'
        '<circle cx="24" cy="20" r="6" fill="#FF5F57"/>'
        '<circle cx="44" cy="20" r="6" fill="#FEBC2E"/>'
        '<circle cx="64" cy="20" r="6" fill="#28C840"/>'
        f'<text x="{W/2:.0f}" y="25" text-anchor="middle" fill="#8B98AD" '
        f'font-family="{MONO}" font-size="13">arp-spoofer — lan assessment</text>'
        f'<svg x="18" y="58" width="{VIEW_W}" height="{VIEW_H}" '
        f'viewBox="0 0 {VIEW_W} {VIEW_H}" overflow="hidden">'
        f'{strip_open}font-family="{MONO}" font-size="{FS}" xml:space="preserve">'
        f'{strip_items}</g></svg></svg>\n')
    return finish(svg, {("JBM", 400), ("JBM", 700)})


if __name__ == "__main__":
    DOCS.mkdir(exist_ok=True)
    if len(sys.argv) >= 3 and sys.argv[1] == "--static":
        Path("/tmp/demo-static.svg").write_text(render(static_frame=int(sys.argv[2])), encoding="utf-8")
        print("wrote /tmp/demo-static.svg")
    else:
        p = DOCS / "demo.svg"
        p.write_text(render(), encoding="utf-8")
        print("wrote", p, f"({len(render())//1024} KB, animated)")
