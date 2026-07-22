"""Generate assets/demo.svg — a self-contained terminal screenshot of the demo.

Renders the otgate demo's decision output as an SVG "terminal window" that
GitHub shows natively in the README (no external JS, a few KB, crisp at any
size). Colours match the terminal: ALLOW/APPROVED green, ASK yellow,
DENY/DENIED red. Run:  python assets/make_demo_svg.py
"""

from __future__ import annotations

import html
from pathlib import Path

# (text, colour-key) segments per line. colour-key None => default foreground.
FG = "#c8d3f5"
DIM = "#7a88cf"
GREEN = "#4fd6be"
YELLOW = "#ffc777"
RED = "#ff757f"
CYAN = "#86e1fc"
BG = "#1a1b26"
BAR = "#24283b"

PROMPT = [("$ ", CYAN), ("python examples/demo.py", FG)]

# Each row: list of (text, colour). Kept aligned to the real demo output.
ROWS: list[list[tuple[str, str]]] = [
    PROMPT,
    [("", FG)],
    [("otgate — LLM agent writing to an industrial OPC UA reactor, gated by policy", DIM)],
    [("", FG)],
    [("  read temperature (PV)                      ", FG), ("ALLOW", GREEN),
     ("  read allowed → 55.0", FG)],
    [("  write setpoint = 60°C (in range)           ", FG), ("ASK", YELLOW),
     ("    needs human approval", FG)],
    [("    → operator approves                      ", DIM), ("APPROVED", GREEN),
     ("  executed → server now 60.0", FG)],
    [("  write setpoint = 200°C (out of range)      ", FG), ("DENY", RED),
     ("   outside allowed range [40, 80]", FG)],
    [("  write setpoint = 60°C while ESD active     ", FG), ("DENY", RED),
     ("   interlock active: Reactor.ESD == True", FG)],
    [("  write setpoint = 58°C, approve after ESD   ", FG), ("DENIED", RED),
     (" blocked on re-check (interlock)", FG)],
    [("  write setpoint = 78°C one second later     ", FG), ("DENY", RED),
     ("   rate too high: 28 in 1s > 5 per 60s", FG)],
    [("", FG)],
    [("  every call is recorded in an append-only audit log.", DIM)],
]

CHAR_W = 8.4
LINE_H = 22
PAD_X = 20
TOP = 52  # room for the title bar
FONT = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
        "'Liberation Mono', monospace")


def line_width(row: list[tuple[str, str]]) -> int:
    return sum(len(t) for t, _ in row)


def build() -> str:
    cols = max(line_width(r) for r in ROWS)
    width = int(PAD_X * 2 + cols * CHAR_W)
    height = int(TOP + len(ROWS) * LINE_H + 16)

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{html.escape(FONT)}" '
        f'font-size="14">'
    )
    # window
    parts.append(f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>')
    parts.append(f'<rect width="{width}" height="34" rx="10" fill="{BAR}"/>')
    parts.append(f'<rect y="24" width="{width}" height="10" fill="{BAR}"/>')
    # traffic lights
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        parts.append(f'<circle cx="{20 + i * 20}" cy="17" r="6" fill="{c}"/>')
    parts.append(
        f'<text x="{width/2}" y="22" fill="{DIM}" text-anchor="middle" '
        f'font-size="12">otgate demo</text>'
    )

    y = TOP
    for row in ROWS:
        x = PAD_X
        for text, colour in row:
            if text:
                weight = ' font-weight="700"' if colour in (GREEN, YELLOW, RED) else ""
                parts.append(
                    f'<text x="{x:.1f}" y="{y}" fill="{colour}" '
                    f'xml:space="preserve"{weight}>{html.escape(text)}</text>'
                )
            x += len(text) * CHAR_W
        y += LINE_H

    parts.append("</svg>")
    return "".join(parts)


def main() -> None:
    out = Path(__file__).resolve().parent / "demo.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
