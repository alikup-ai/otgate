"""Generate assets/demo.gif — an animated diagram of what otgate actually does.

assets/demo.svg already shows the *decisions*: a static list of ALLOW / ASK /
DENY lines with their reasons. This GIF shows the *mechanism* the SVG cannot —
the agent's write being intercepted, the policy checks running in their fixed
order, the check that fails, and where the request ends up. Four scenarios run
in a loop: an approved write that reaches the server, and three refusals for
three different process reasons.

Design notes, if you are regenerating this:

* Flat colours only. GIF is palette-indexed with no alpha, so gradients and
  soft shadows band badly. Everything here is solid fills plus antialiased
  text, which survives quantisation.
* One shared palette for every frame, derived from a montage of sampled frames.
  Quantising each frame independently makes the background shimmer.
* Geometry and timing are in the constants below; nothing is hard-coded twice.

Run:  python assets/make_demo_gif.py
Needs Pillow (`pip install pillow`); it is not an otgate dependency, this is a
one-off asset build.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# --- palette: Tokyo Night, matching assets/demo.svg -------------------------
BG = (26, 27, 38)
CARD = (36, 40, 59)
EDGE = (47, 53, 73)
FG = (200, 211, 245)
DIM = (122, 136, 207)
FAINT = (86, 95, 137)
GREEN = (79, 214, 190)
YELLOW = (255, 199, 119)
RED = (255, 117, 127)
CYAN = (134, 225, 252)
VIOLET = (187, 154, 247)

W, H = 900, 462

# --- layout -----------------------------------------------------------------
# The gate box has to fit six check rows *and* the verdict badge underneath
# them; sizing it to the rows alone makes the badge sit on the last row.
AGENT = (28, 92, 214, 196)          # x0, y0, x1, y1
GATE = (266, 64, 650, 334)
SERVER = (686, 92, 872, 196)
LANE_Y = 144                         # centre line the packet travels along
AUDIT_Y = 362
CHECK_X = 288
CHECK_Y0 = 124
CHECK_DY = 28
STATUS_X = GATE[2] - 52
NOTE_X = CHECK_X + 118
BADGE_Y = 290                        # clear of the last row at CHECK_Y0 + 5*DY

# Notes are kept short on purpose: they have to fit between NOTE_X and
# STATUS_X, and an overlong one silently collides with the status column.
CHECKS = [
    ("value_range", "inside the allowed band"),
    ("interlocks", "guard tags read live"),
    ("max_rate", "vs the live value"),
    ("cumulative", "drift over a window"),
    ("max_calls", "call budget"),
    ("approval", "human, separate channel"),
]

MONO_CANDIDATES = [
    "CascadiaMono.ttf", "consola.ttf", "DejaVuSansMono.ttf",
    "LiberationMono-Regular.ttf", "Menlo.ttc", "SFNSMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
MONO_BOLD_CANDIDATES = [
    "CascadiaMono-Bold.ttf", "consolab.ttf", "DejaVuSansMono-Bold.ttf",
    "LiberationMono-Bold.ttf",
] + MONO_CANDIDATES
SANS_CANDIDATES = [
    "seguisb.ttf", "segoeui.ttf", "DejaVuSans.ttf",
    "LiberationSans-Regular.ttf", "Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def font(candidates: list[str], size: int):
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    print(f"  ! no TrueType font found for size {size}; falling back to bitmap")
    return ImageFont.load_default()


F_TITLE = font(SANS_CANDIDATES, 18)
F_SUB = font(MONO_CANDIDATES, 12)
F_BOX = font(MONO_BOLD_CANDIDATES, 13)
F_CHECK = font(MONO_CANDIDATES, 13)
F_NOTE = font(MONO_CANDIDATES, 11)
F_BADGE = font(MONO_BOLD_CANDIDATES, 14)
F_PKT = font(MONO_BOLD_CANDIDATES, 12)


# --- scenarios --------------------------------------------------------------
# fail_at: index into CHECKS, or None when every check passes.
# verdict: (badge, colour, reason shown under the gate)
SCENARIOS = [
    {
        "call": "write  TIC101.SP = 59.0",
        "why": "in range, inside the rate allowance",
        "fail_at": None,
        "stop_at": 5,                     # reaches the approval check
        "verdict": ("ASK", YELLOW, "parked for a human — agent cannot self-approve"),
        "approved": True,
        "server_after": "59.0",
        "audit": '{"decision":"ASK"} then {"decision":"APPROVED","executed":true}',
    },
    {
        "call": "write  TIC101.SP = 200.0",
        "why": "far outside the allowed band",
        "fail_at": 0,
        "verdict": ("DENY", RED, "value 200.0 is outside allowed range [40, 80]"),
        "audit": '{"decision":"DENY","reason":"outside range","executed":false}',
    },
    {
        "call": "write  TIC101.SP = 60.0",
        "why": "in range — but not right now",
        "fail_at": 1,
        "esd": True,
        "verdict": ("DENY", RED, "interlock active: Reactor.ESD == True"),
        "audit": '{"decision":"DENY","reason":"interlock active","executed":false}',
    },
    {
        # The point of this one is that otgate is a soft layer: it cannot assume
        # it is the only thing that ever writes to the plant. The baseline for
        # the rate check is the tag's live value, so a move made by someone else
        # still counts.
        "call": "write  TIC101.SP = 199.0",
        "why": "a small step — from the wrong place",
        "fail_at": 2,
        "moved_outside": ("55.0", "an operator moves the tag at the HMI, bypassing otgate"),
        "verdict": ("DENY", RED, "rate too high: |199.0 - 55.0| = 144 > 5 per 60s"),
        "audit": '{"decision":"DENY","reason":"rate of change too high"}',
    },
]


# --- drawing helpers --------------------------------------------------------
def card(d: ImageDraw.ImageDraw, box, border=EDGE, fill=CARD, width=1, radius=10):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=border, width=width)


def centred(d: ImageDraw.ImageDraw, text, box, fnt, fill):
    x0, y0, x1, y1 = box
    w = d.textlength(text, font=fnt)
    asc, desc = fnt.getmetrics() if hasattr(fnt, "getmetrics") else (10, 2)
    d.text((x0 + (x1 - x0 - w) / 2, (y0 + y1) / 2 - (asc + desc) / 2 + 1),
           text, font=fnt, fill=fill)


def dot(d: ImageDraw.ImageDraw, cx, cy, colour, r=4, hollow=False):
    box = (cx - r, cy - r, cx + r, cy + r)
    if hollow:
        d.ellipse(box, outline=colour, width=2)
    else:
        d.ellipse(box, fill=colour)


def packet(d: ImageDraw.ImageDraw, cx, cy, text, colour):
    w = d.textlength(text, font=F_PKT) + 22
    h = 26
    box = (cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2)
    d.rounded_rectangle(box, radius=7, fill=BG, outline=colour, width=2)
    centred(d, text, box, F_PKT, colour)


def arrow(d: ImageDraw.ImageDraw, x0, x1, y, colour, head=6):
    d.line((x0, y, x1, y), fill=colour, width=2)
    s = 1 if x1 > x0 else -1
    d.polygon([(x1, y), (x1 - s * head, y - head + 1), (x1 - s * head, y + head - 1)],
              fill=colour)


def ease(t: float) -> float:
    """Smoothstep, so the packet does not start and stop abruptly."""
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)


# --- the frame ---------------------------------------------------------------
def render(state: dict) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.text((28, 22), "otgate", font=F_TITLE, fill=CYAN)
    d.text((100, 26), "— every write an agent makes to the plant passes a process-aware policy",
           font=F_SUB, fill=DIM)
    d.text((28, 50), "value ranges · rate of change · live interlocks · drift windows · "
                     "human approval · fail closed",
           font=F_NOTE, fill=FAINT)

    # agent
    card(d, AGENT)
    centred(d, "LLM AGENT", (AGENT[0], AGENT[1] + 14, AGENT[2], AGENT[1] + 40), F_BOX, FG)
    centred(d, "speaks MCP", (AGENT[0], AGENT[1] + 40, AGENT[2], AGENT[1] + 62), F_NOTE, FAINT)
    centred(d, state.get("call", ""), (AGENT[0], AGENT[1] + 64, AGENT[2], AGENT[1] + 86),
            F_NOTE, CYAN if state.get("call") else FAINT)
    why = state.get("why", "")
    if why:
        # Left-aligned to the canvas margin: centring this on the agent box
        # pushed longer captions off the left edge.
        d.text((AGENT[0] + 8, AGENT[3] + 10), why, font=F_NOTE, fill=FAINT)

    # gateway
    active = state.get("phase") in {"check", "verdict", "approve"}
    card(d, GATE, border=CYAN if active else EDGE, width=2 if active else 1)
    centred(d, "otgate", (GATE[0], GATE[1] + 8, GATE[2], GATE[1] + 30), F_BOX, CYAN)
    centred(d, "an MCP server to the agent, an OPC UA client to the plant",
            (GATE[0], GATE[1] + 28, GATE[2], GATE[1] + 48), F_NOTE, FAINT)

    results = state.get("results", {})
    for i, (name, note) in enumerate(CHECKS):
        y = CHECK_Y0 + i * CHECK_DY
        res = results.get(i)
        if res == "pass":
            col, mark = GREEN, "ok"
        elif res == "fail":
            col, mark = RED, "DENY"
        elif res == "ask":
            col, mark = YELLOW, "ASK"
        elif res == "busy":
            col, mark = CYAN, "…"
        else:
            col, mark = FAINT, ""
        dot(d, CHECK_X, y + 7, col, hollow=res is None)
        d.text((CHECK_X + 14, y), name, font=F_CHECK, fill=col if res else FAINT)
        d.text((NOTE_X, y + 1), note, font=F_NOTE, fill=DIM if res else FAINT)
        if mark:
            d.text((STATUS_X, y), mark, font=F_NOTE, fill=col)

    verdict = state.get("verdict")
    if verdict:
        badge, colour, reason = verdict
        bx = (GATE[0] + 14, BADGE_Y, GATE[0] + 14 + 82, BADGE_Y + 28)
        d.rounded_rectangle(bx, radius=6, fill=colour)
        centred(d, badge, bx, F_BADGE, BG)
        d.text((bx[2] + 12, BADGE_Y + 7), reason, font=F_NOTE, fill=colour)

    # server
    esd = state.get("esd")
    card(d, SERVER, border=RED if esd else EDGE, width=2 if esd else 1)
    centred(d, "OPC UA", (SERVER[0], SERVER[1] + 12, SERVER[2], SERVER[1] + 34), F_BOX, FG)
    centred(d, "reactor", (SERVER[0], SERVER[1] + 30, SERVER[2], SERVER[1] + 50), F_NOTE, FAINT)
    centred(d, f"TIC101.SP {state.get('sp', '55.0')}",
            (SERVER[0], SERVER[1] + 52, SERVER[2], SERVER[1] + 72), F_NOTE, FG)
    centred(d, "ESD ACTIVE" if esd else "ESD clear",
            (SERVER[0], SERVER[1] + 70, SERVER[2], SERVER[1] + 90), F_NOTE,
            RED if esd else FAINT)

    # lanes
    arrow(d, AGENT[2] + 8, GATE[0] - 8, LANE_Y, EDGE)
    reach = state.get("reaches_server")
    arrow(d, GATE[2] + 8, SERVER[0] - 8, LANE_Y, GREEN if reach else EDGE)
    if not reach and state.get("phase") in {"verdict", "bounce"}:
        d.text(((GATE[2] + SERVER[0]) / 2 - 22, LANE_Y + 10), "blocked",
               font=F_NOTE, fill=FAINT)

    pkt = state.get("packet")
    if pkt:
        px, text, colour = pkt
        packet(d, px, LANE_Y, text, colour)

    # audit strip
    card(d, (28, AUDIT_Y, 872, AUDIT_Y + 64), radius=8)
    d.text((44, AUDIT_Y + 12), "append-only audit log", font=F_NOTE, fill=FAINT)
    line = state.get("audit")
    if line:
        d.text((44, AUDIT_Y + 32), line, font=F_NOTE, fill=state.get("audit_colour", DIM))

    d.text((W - 232, H - 18), "github.com/alikup-ai/otgate", font=F_NOTE, fill=FAINT)
    return img


# --- the script -------------------------------------------------------------
frames: list[Image.Image] = []
durations: list[int] = []


def add(state: dict, ms: int, n: int = 1) -> None:
    img = render(state)
    for _ in range(n):
        frames.append(img.copy())
        durations.append(ms)


def run() -> None:
    sp = "55.0"
    for sc in SCENARIOS:
        base = {
            "call": sc["call"], "why": sc["why"], "sp": sp,
            "esd": sc.get("esd", False), "results": {},
        }

        # idle beat, so the loop has a readable resting point
        add({**base, "phase": "idle"}, 420)

        # something other than otgate moves the tag
        moved = sc.get("moved_outside")
        if moved:
            sp, caption = moved
            base["sp"] = sp
            add({**base, "phase": "idle", "audit": caption, "audit_colour": VIOLET}, 1500)

        # the request travels to the gateway
        x0, x1 = AGENT[2] + 60, GATE[0] - 30
        steps = 6
        for i in range(steps):
            px = x0 + (x1 - x0) * ease(i / (steps - 1))
            add({**base, "phase": "travel", "packet": (px, sc["call"].split("=")[-1].strip(), CYAN)}, 55)

        # checks run in order
        results: dict[int, str] = {}
        fail_at = sc["fail_at"]
        last = fail_at if fail_at is not None else sc.get("stop_at", len(CHECKS) - 1)
        for i in range(last + 1):
            results[i] = "busy"
            add({**base, "phase": "check", "results": dict(results)}, 150)
            if i == fail_at:
                results[i] = "fail"
            elif i == last and sc["fail_at"] is None:
                results[i] = "ask"
            else:
                results[i] = "pass"
            add({**base, "phase": "check", "results": dict(results)}, 190)

        # verdict
        v = sc["verdict"]
        add({**base, "phase": "verdict", "results": dict(results), "verdict": v,
             "audit": sc["audit"], "audit_colour": v[1]}, 1500)

        if sc.get("approved"):
            # the operator resolves it on the other channel, policy is re-checked,
            # and only then does the write reach the plant
            add({**base, "phase": "approve", "results": dict(results), "verdict": v,
                 "audit": "operator approves on the operator channel → policy re-checked",
                 "audit_colour": YELLOW}, 1100)
            ok = {i: "pass" for i in range(len(CHECKS))}
            add({**base, "phase": "approve", "results": ok,
                 "verdict": ("APPROVED", GREEN, "re-checked against the current process state"),
                 "audit": sc["audit"], "audit_colour": GREEN}, 900)
            gx0, gx1 = GATE[2] + 26, SERVER[0] - 28
            for i in range(6):
                px = gx0 + (gx1 - gx0) * ease(i / 5)
                add({**base, "phase": "approve", "results": ok, "reaches_server": True,
                     "packet": (px, sc["call"].split("=")[-1].strip(), GREEN),
                     "verdict": ("APPROVED", GREEN, "executed"),
                     "audit": sc["audit"], "audit_colour": GREEN}, 55)
            sp = sc["server_after"]
            add({**base, "phase": "approve", "results": ok, "reaches_server": True, "sp": sp,
                 "verdict": ("APPROVED", GREEN, "executed — server now 59.0"),
                 "audit": sc["audit"], "audit_colour": GREEN}, 1500)
        else:
            # refused: the request goes back to the agent with a reason, and the
            # plant never sees it
            gx0, gx1 = GATE[0] - 30, AGENT[2] + 56
            for i in range(6):
                px = gx0 + (gx1 - gx0) * ease(i / 5)
                add({**base, "phase": "bounce", "results": dict(results), "verdict": v,
                     "packet": (px, v[0], v[1]), "audit": sc["audit"],
                     "audit_colour": v[1]}, 55)
            add({**base, "phase": "bounce", "results": dict(results), "verdict": v,
                 "audit": sc["audit"], "audit_colour": v[1]}, 1100)

    # closing beat
    add({"sp": sp, "results": {}, "phase": "idle",
         "audit": "nothing reached the plant that the policy did not allow.",
         "audit_colour": GREEN}, 1800)


def quantise(imgs: list[Image.Image]) -> list[Image.Image]:
    """One shared palette for every frame.

    Quantising frames independently lets the background dither differently from
    one frame to the next, which reads as a shimmer across the whole image.
    Sampling a montage gives a palette that covers every colour that appears,
    including the blends text antialiasing produces.
    """
    sample = imgs[:: max(1, len(imgs) // 24)]
    montage = Image.new("RGB", (W, H * len(sample)))
    for i, im in enumerate(sample):
        montage.paste(im, (0, i * H))
    pal = montage.quantize(colors=64, method=Image.Quantize.MEDIANCUT)
    return [im.quantize(palette=pal, dither=Image.Dither.NONE) for im in imgs]


def main() -> None:
    run()
    out = Path(__file__).resolve().parent / "demo.gif"
    print(f"  rendered {len(frames)} frames, {sum(durations) / 1000:.1f}s loop")
    q = quantise(frames)
    # disposal=1 (leave the previous frame in place) is what lets `optimize`
    # store just the changed rectangle. With disposal=2 every frame is written
    # whole and the file is several times larger for an identical animation.
    q[0].save(
        out, save_all=True, append_images=q[1:], duration=durations,
        loop=0, optimize=True, disposal=1,
    )
    print(f"  wrote {out} ({out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
