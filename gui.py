"""Tkinter front end for the demo.

    uv run gui.py

Shows Alice, Bob and (optionally) Mallory as nodes on a diagram, animates
every packet along the wire, and lists the keys each party holds as it
acquires them. Keys 1-4 run the four scenarios; Enter runs the custom one.

The protocol runs on the Tk main loop as a generator (`App._scenario`) that
mirrors `demo.run` step by step, pausing after each call so the matching hop
can be animated.
"""

import tkinter as tk
from dataclasses import dataclass, field
from tkinter import font as tkfont

import demo
import output
import primitives
from output import heading
from parties import Alice, Bob, Channel, Mallory

# --- Theme ----------------------------------------------------------------------------

BG = "#0e1117"
PANEL = "#151923"
SURFACE = "#1c2230"
SURFACE_HOVER = "#242c3d"
BORDER = "#2a3244"
TEXT = "#e6e9ef"
MUTED = "#8a93a6"
ACCENT = "#a78bfa"
WARN = "#f59e0b"

PARTY_COLORS = {
    "ALICE": "#60a5fa",
    "BOB": "#34d399",
    "MALLORY": "#f87171",
    "CHANNEL": "#9ca3af",
}

VERDICT_STYLES = {
    "idle": (SURFACE, MUTED),
    "running": (SURFACE, TEXT),
    "ok": ("#0f3d2e", "#6ee7b7"),
    "detected": ("#42300c", "#fcd34d"),
    "attack": ("#4a1717", "#fca5a5"),
    "blocked": ("#172a52", "#93c5fd"),
}

UI_FONTS = ["Inter", "Adwaita Sans", "Segoe UI", "SF Pro Text", "Helvetica Neue",
            "Noto Sans", "Cantarell", "DejaVu Sans", "Liberation Sans", "Helvetica"]
MONO_FONTS = ["JetBrains Mono", "Cascadia Mono", "Consolas", "Menlo", "Adwaita Mono",
              "Hack", "DejaVu Sans Mono", "Liberation Mono", "Courier New"]

PRESETS = [
    ("Normal conversation", "Hybrid encryption with nobody in the way.",
     dict(mitm=False, sign=False, corrupt=False)),
    ("Flip one bit", "The network corrupts one bit; the GCM tag catches it.",
     dict(mitm=False, sign=False, corrupt=True)),
    ("Mallory in the middle", "Mallory swaps Bob's key, reads and edits everything.",
     dict(mitm=True, sign=False, corrupt=False)),
    ("Mallory vs. signature", "Bob signs his key; the swap is caught at once.",
     dict(mitm=True, sign=True, corrupt=False)),
]

HOP_MS = 650  # duration of one animated hop at 1x speed


def mix(a: str, b: str, t: float) -> str:
    """Blend two #rrggbb colors; t=0 gives a, t=1 gives b."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


def pick_font(root: tk.Tk, candidates: list[str], fallback: str) -> str:
    available = set(tkfont.families(root))
    return next((name for name in candidates if name in available), tkfont.nametofont(fallback).actual("family"))


def rounded_rect(canvas: tk.Canvas, x1, y1, x2, y2, r=10, **kw) -> int:
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    points = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
              x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(points, smooth=True, **kw)


def verdict(result: demo.Result, mitm: bool, sent: list[str]) -> tuple[str, str]:
    """Return (style, text) summarizing a finished run."""
    if not result.handshake_ok:
        return "blocked", "Attack blocked — the signature did not match and Alice aborted"
    if mitm and result.bob_received != sent:
        return "attack", "Attack succeeded — Mallory read the messages and Bob got altered ones"
    if mitm:
        return "attack", "Attack succeeded — Mallory read every message"
    if result.bob_rejected:
        return "detected", f"Tampering detected — Bob rejected {result.bob_rejected} message(s)"
    return "ok", "Delivered intact — only Alice and Bob could read the messages"


# --- Diagram state ----------------------------------------------------------------------

@dataclass
class Chip:
    text: str
    color: str


@dataclass
class DiagramState:
    mitm: bool = False
    chips: dict[str, list[Chip]] = field(default_factory=lambda: {"ALICE": [], "BOB": [], "MALLORY": []})
    status: dict[str, str] = field(default_factory=lambda: {"ALICE": "", "BOB": "", "MALLORY": ""})
    flash: dict[str, str] = field(default_factory=dict)


# --- Custom widgets ---------------------------------------------------------------------

class Toggle(tk.Canvas):
    """A small on/off switch bound to a BooleanVar."""

    def __init__(self, parent, variable: tk.BooleanVar, color: str, bg: str):
        super().__init__(parent, width=40, height=22, bg=bg, highlightthickness=0, cursor="hand2")
        self.variable, self.color = variable, color
        self.bind("<Button-1>", lambda _: variable.set(not variable.get()))
        variable.trace_add("write", lambda *_: self._draw())
        self._draw()

    def _draw(self):
        self.delete("all")
        on = self.variable.get()
        rounded_rect(self, 1, 1, 39, 21, r=10, fill=self.color if on else BORDER, outline="")
        x = 28 if on else 12
        self.create_oval(x - 8, 3, x + 8, 19, fill=TEXT if on else MUTED, outline="")


class FlatButton(tk.Label):
    def __init__(self, parent, text: str, command, bg: str, fg: str, font, hover: str):
        super().__init__(parent, text=text, bg=bg, fg=fg, font=font, pady=10, cursor="hand2")
        self.command, self.bg, self.hover, self.enabled = command, bg, hover, True
        self.bind("<Button-1>", lambda _: self.enabled and self.command())
        self.bind("<Enter>", lambda _: self.enabled and self.configure(bg=self.hover))
        self.bind("<Leave>", lambda _: self.configure(bg=self.bg if self.enabled else BORDER))

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        self.configure(bg=self.bg if enabled else BORDER, cursor="hand2" if enabled else "arrow")


class ScenarioCard(tk.Frame):
    def __init__(self, parent, index: int, title: str, description: str, command, fonts):
        super().__init__(parent, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
        self.selected = False
        header = tk.Frame(self, bg=SURFACE)
        header.pack(fill=tk.X, padx=12, pady=(10, 2))
        self.badge = tk.Label(header, text=str(index + 1), width=2, bg=BORDER, fg=TEXT, font=fonts["small_bold"])
        self.badge.pack(side=tk.LEFT)
        self.title = tk.Label(header, text=title, bg=SURFACE, fg=TEXT, font=fonts["bold"])
        self.title.pack(side=tk.LEFT, padx=(8, 0))
        self.desc = tk.Label(self, text=description, bg=SURFACE, fg=MUTED, font=fonts["small"],
                             wraplength=250, justify=tk.LEFT, anchor="w")
        self.desc.pack(fill=tk.X, padx=12, pady=(0, 10))
        for widget in (self, header, self.badge, self.title, self.desc):
            widget.bind("<Button-1>", lambda _: command())
            widget.bind("<Enter>", lambda _: self._paint(SURFACE_HOVER))
            widget.bind("<Leave>", lambda _: self._paint(SURFACE))

    def _paint(self, bg: str):
        for widget in (self, self.title, self.desc, self.title.master):
            widget.configure(bg=bg)

    def set_selected(self, selected: bool):
        self.selected = selected
        self.configure(highlightbackground=ACCENT if selected else BORDER)
        self.badge.configure(bg=ACCENT if selected else BORDER, fg=BG if selected else TEXT)


# --- Application ------------------------------------------------------------------------

class App:
    def __init__(self, root: tk.Tk, animate: bool = True):
        self.root = root
        self.animate = animate
        self.running = False
        self.last_verdict: tuple[str, str] | None = None
        self.state = DiagramState()
        self._steps = None
        self._packet: list[int] = []
        self._applying_preset = False

        ui = pick_font(root, UI_FONTS, "TkDefaultFont")
        mono = pick_font(root, MONO_FONTS, "TkFixedFont")
        self.fonts = {
            "title": (ui, 17, "bold"),
            "bold": (ui, 11, "bold"),
            "body": (ui, 11),
            "small": (ui, 10),
            "small_bold": (ui, 10, "bold"),
            "section": (ui, 9, "bold"),
            "node": (ui, 14, "bold"),
            "chip": (ui, 9),
            "packet": (ui, 10, "bold"),
            "banner": (ui, 12, "bold"),
            "mono": (mono, 11),
            "mono_bold": (mono, 11, "bold"),
        }

        root.title("Hybrid Encryption Lab")
        root.configure(bg=BG)
        root.geometry("1380x860")
        root.minsize(1100, 700)

        self.mitm = tk.BooleanVar()
        self.sign = tk.BooleanVar()
        self.corrupt = tk.BooleanVar()
        self.speed = tk.DoubleVar(value=1.0)
        self.old_text = tk.StringVar(value=demo.DEFAULT_REPLACEMENTS[0][0])
        self.new_text = tk.StringVar(value=demo.DEFAULT_REPLACEMENTS[0][1])

        self._build_sidebar()
        self._build_main()

        for var in (self.mitm, self.sign, self.corrupt):
            var.trace_add("write", lambda *_: self._on_options_changed())
        for i in range(len(PRESETS)):
            root.bind(str(i + 1), lambda _, i=i: self._key_preset(i))
        root.bind("<Return>", lambda e: None if isinstance(e.widget, tk.Text) else self.run())

        output.configure()
        output.set_sink(self._append)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._set_banner("idle", "Pick a scenario on the left, or press 1-4")
        self.root.after(50, self._redraw)

    # --- layout -----------------------------------------------------------------------

    def _build_sidebar(self):
        side = tk.Frame(self.root, bg=PANEL, width=310)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)
        inner = tk.Frame(side, bg=PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)

        tk.Label(inner, text="Hybrid Encryption Lab", bg=PANEL, fg=TEXT, font=self.fonts["title"]).pack(anchor="w")
        tk.Label(inner, text="AES-256-GCM · RSA-2048-OAEP · Ed25519", bg=PANEL, fg=MUTED,
                 font=self.fonts["small"]).pack(anchor="w", pady=(2, 14))

        self._section(inner, "SCENARIOS")
        self.cards = []
        for i, (title, desc, _) in enumerate(PRESETS):
            card = ScenarioCard(inner, i, title, desc, lambda i=i: self.run_preset(i), self.fonts)
            card.pack(fill=tk.X, pady=3)
            self.cards.append(card)

        self._section(inner, "CUSTOM RUN", top=16)
        for text, var, color in (
            ("Mallory in the middle", self.mitm, PARTY_COLORS["MALLORY"]),
            ("Bob signs his key", self.sign, PARTY_COLORS["BOB"]),
            ("Flip one bit in transit", self.corrupt, WARN),
        ):
            row = tk.Frame(inner, bg=PANEL)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=text, bg=PANEL, fg=TEXT, font=self.fonts["body"]).pack(side=tk.LEFT)
            Toggle(row, var, color, PANEL).pack(side=tk.RIGHT)

        tk.Label(inner, text="Messages, one per line", bg=PANEL, fg=MUTED,
                 font=self.fonts["small"]).pack(anchor="w", pady=(10, 3))
        self.messages = tk.Text(inner, height=3, wrap="word", bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                                relief=tk.FLAT, font=self.fonts["small"], padx=8, pady=6,
                                highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT)
        self.messages.insert("1.0", "\n".join(demo.DEFAULT_MESSAGES))
        self.messages.pack(fill=tk.X)

        tk.Label(inner, text="Mallory replaces", bg=PANEL, fg=MUTED,
                 font=self.fonts["small"]).pack(anchor="w", pady=(10, 3))
        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill=tk.X)
        for i, var in enumerate((self.old_text, self.new_text)):
            tk.Entry(row, textvariable=var, width=11, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                     relief=tk.FLAT, font=self.fonts["small"], highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=ACCENT).pack(side=tk.LEFT, ipady=4)
            if i == 0:
                tk.Label(row, text="→", bg=PANEL, fg=MUTED, font=self.fonts["body"]).pack(side=tk.LEFT, padx=6)

        speed_row = tk.Frame(inner, bg=PANEL)
        speed_row.pack(fill=tk.X, pady=(12, 0))
        tk.Label(speed_row, text="Animation speed", bg=PANEL, fg=MUTED, font=self.fonts["small"]).pack(side=tk.LEFT)
        self.speed_label = tk.Label(speed_row, text="1.0×", bg=PANEL, fg=TEXT, font=self.fonts["small_bold"])
        self.speed_label.pack(side=tk.RIGHT)
        tk.Scale(inner, from_=0.5, to=3.0, resolution=0.25, orient=tk.HORIZONTAL, variable=self.speed,
                 showvalue=False, bg=PANEL, troughcolor=SURFACE, activebackground=ACCENT, highlightthickness=0,
                 sliderrelief=tk.FLAT, bd=0, width=10,
                 command=lambda v: self.speed_label.configure(text=f"{float(v):.2g}×")).pack(fill=tk.X)

        self.run_button = FlatButton(inner, "Run  ⏎", self.run, ACCENT, BG, self.fonts["bold"], mix(ACCENT, TEXT, 0.25))
        self.run_button.pack(fill=tk.X, pady=(14, 0))

    def _section(self, parent, text: str, top: int = 0):
        tk.Label(parent, text=text, bg=PANEL, fg=MUTED, font=self.fonts["section"]).pack(anchor="w", pady=(top, 6))

    def _build_main(self):
        main = tk.Frame(self.root, bg=BG)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=18, pady=18)

        self.banner = tk.Label(main, anchor="w", padx=16, pady=12, font=self.fonts["banner"])
        self.banner.pack(fill=tk.X)

        self.canvas = tk.Canvas(main, height=330, bg=BG, highlightthickness=0)
        self.canvas.pack(fill=tk.X, pady=(12, 8))
        self.canvas.bind("<Configure>", lambda _: self._redraw())

        header = tk.Frame(main, bg=BG)
        header.pack(fill=tk.X, pady=(4, 6))
        tk.Label(header, text="EVENT LOG", bg=BG, fg=MUTED, font=self.fonts["section"]).pack(side=tk.LEFT)
        for party in ("CHANNEL", "MALLORY", "BOB", "ALICE"):
            tk.Label(header, text=f"●  {party.title()}", bg=BG, fg=PARTY_COLORS[party],
                     font=self.fonts["small"]).pack(side=tk.RIGHT, padx=(12, 0))

        frame = tk.Frame(main, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        frame.pack(fill=tk.BOTH, expand=True)
        self.log = tk.Text(frame, wrap="word", bg=PANEL, fg=TEXT, relief=tk.FLAT, font=self.fonts["mono"],
                           padx=14, pady=10, state=tk.DISABLED, highlightthickness=0, cursor="arrow",
                           spacing1=2, spacing3=2)
        scroll = tk.Scrollbar(frame, command=self.log.yview, bg=PANEL, troughcolor=PANEL,
                              activebackground=BORDER, highlightthickness=0, bd=0, width=10)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log.tag_configure("heading", foreground=ACCENT, font=self.fonts["bold"], spacing1=12, spacing3=4)
        self.log.tag_configure("alert", foreground=PARTY_COLORS["MALLORY"], font=self.fonts["mono_bold"])
        for party, color in PARTY_COLORS.items():
            self.log.tag_configure(party, foreground=color, font=self.fonts["mono_bold"])

    # --- diagram ----------------------------------------------------------------------

    def _geometry(self) -> dict:
        w = max(self.canvas.winfo_width(), 800)
        node_w = min(300, w * 0.27)
        wire_y = 70
        return {
            "w": w,
            "ALICE": (8, 12, 8 + node_w, 212),
            "BOB": (w - 8 - node_w, 12, w - 8, 212),
            "MALLORY": (w / 2 - node_w / 2, 180, w / 2 + node_w / 2, 322),
            "anchor": {
                "ALICE": (8 + node_w, wire_y),
                "BOB": (w - 8 - node_w, wire_y),
                "MID": (w / 2, wire_y),
                "MALLORY": (w / 2, 180),
            },
        }

    def _redraw(self):
        c = self.canvas
        c.delete("static")
        g = self._geometry()
        a, b, m = g["anchor"]["ALICE"], g["anchor"]["BOB"], g["anchor"]["MALLORY"]

        if self.state.mitm:
            c.create_line(*a, *m, *b, fill=mix(PARTY_COLORS["MALLORY"], BG, 0.35), width=3,
                          joinstyle=tk.ROUND, tags="static")
            c.create_line(*a, *b, fill=BORDER, width=2, dash=(4, 6), tags="static")
        else:
            c.create_line(*a, *b, fill=BORDER, width=3, tags="static")
        c.create_text(g["w"] / 2, a[1] - 18, text="insecure channel", fill=MUTED,
                      font=self.fonts["small"], tags="static")

        roles = {"ALICE": "sender", "BOB": "receiver", "MALLORY": "attacker"}
        for party in ("ALICE", "BOB", "MALLORY"):
            present = party != "MALLORY" or self.state.mitm
            self._draw_node(g[party], party, roles[party], present)

        c.tag_raise("packet")

    def _draw_node(self, box, party: str, role: str, present: bool):
        c = self.canvas
        x1, y1, x2, y2 = box
        color = PARTY_COLORS[party]
        if not present:
            rounded_rect(c, x1, y1, x2, y2, r=14, fill=BG, outline=BORDER, dash=(4, 4), tags="static")
            c.create_text((x1 + x2) / 2, (y1 + y2) / 2 - 8, text="Mallory", fill=MUTED,
                          font=self.fonts["node"], tags="static")
            c.create_text((x1 + x2) / 2, (y1 + y2) / 2 + 16, text="not on the line", fill=MUTED,
                          font=self.fonts["small"], tags="static")
            return

        outline = self.state.flash.get(party, mix(color, BG, 0.45))
        rounded_rect(c, x1, y1, x2, y2, r=14, fill=SURFACE, outline=outline,
                     width=3 if party in self.state.flash else 2, tags="static")
        c.create_oval(x1 + 16, y1 + 20, x1 + 28, y1 + 32, fill=color, outline="", tags="static")
        c.create_text(x1 + 38, y1 + 26, text=party.title(), anchor="w", fill=TEXT,
                      font=self.fonts["node"], tags="static")
        c.create_text(x2 - 16, y1 + 26, text=role, anchor="e", fill=MUTED, font=self.fonts["small"], tags="static")

        status = self.state.status[party]
        if status:
            alarming = "ABORTED" in status or ("rejected" in status and "rejected 0" not in status)
            status_color = PARTY_COLORS["MALLORY"] if alarming else MUTED
            c.create_text(x1 + 16, y1 + 50, text=status, anchor="w", fill=status_color,
                          font=self.fonts["small_bold"], tags="static")

        chip_font = tkfont.Font(font=self.fonts["chip"])
        x, y = x1 + 14, y1 + 70
        for chip in self.state.chips[party]:
            tw = chip_font.measure(chip.text) + 18
            if x + tw > x2 - 14:
                x, y = x1 + 14, y + 28
            rounded_rect(c, x, y, x + tw, y + 22, r=11, fill=mix(chip.color, SURFACE, 0.78),
                         outline=mix(chip.color, SURFACE, 0.3), tags="static")
            c.create_text(x + tw / 2, y + 11, text=chip.text, fill=mix(chip.color, TEXT, 0.35),
                          font=self.fonts["chip"], tags="static")
            x += tw + 6

    def _flash(self, party: str, color: str):
        self.state.flash[party] = color
        self._redraw()

        def clear():
            self.state.flash.pop(party, None)
            self._redraw()
        self.root.after(self._ms(700), clear)

    # --- animation --------------------------------------------------------------------

    def _ms(self, base: float) -> int:
        return int(base / self.speed.get()) if self.animate else 0

    def _animate_hop(self, src: str, dst: str, label: str, color: str, style: str, done):
        c = self.canvas
        for item in self._packet:
            c.delete(item)
        g = self._geometry()
        (x0, y0), (x1, y1) = g["anchor"][src], g["anchor"][dst]
        tw = tkfont.Font(font=self.fonts["packet"]).measure(label) + 26
        fill = {"normal": mix(color, BG, 0.55), "forged": mix(PARTY_COLORS["MALLORY"], BG, 0.5),
                "corrupt": mix(WARN, BG, 0.4)}[style]
        outline = {"normal": color, "forged": PARTY_COLORS["MALLORY"], "corrupt": WARN}[style]
        body = rounded_rect(c, -tw / 2, -14, tw / 2, 14, r=14, fill=fill, outline=outline, width=2, tags="packet")
        text = c.create_text(0, 0, text=label, fill=TEXT, font=self.fonts["packet"], tags="packet")
        self._packet = [body, text]
        c.move("packet", x0, y0)

        duration = self._ms(HOP_MS)
        frames = max(1, duration // 16)
        state = {"i": 0, "x": x0, "y": y0}

        def step():
            state["i"] += 1
            t = state["i"] / frames
            t = t * t * (3 - 2 * t)  # smoothstep easing
            nx, ny = x0 + (x1 - x0) * t, y0 + (y1 - y0) * t
            c.move("packet", nx - state["x"], ny - state["y"])
            state["x"], state["y"] = nx, ny
            if state["i"] < frames:
                self.root.after(16, step)
            else:
                done()
        self.root.after(16 if self.animate else 0, step)

    # --- running ----------------------------------------------------------------------

    def _key_preset(self, index: int):
        if not isinstance(self.root.focus_get(), (tk.Text, tk.Entry)):
            self.run_preset(index)

    def run_preset(self, index: int):
        if self.running:
            return
        options = PRESETS[index][2]
        self._applying_preset = True
        self.mitm.set(options["mitm"])
        self.sign.set(options["sign"])
        self.corrupt.set(options["corrupt"])
        self._applying_preset = False
        for i, card in enumerate(self.cards):
            card.set_selected(i == index)
        self.run(title=PRESETS[index][0])

    def _on_options_changed(self):
        if not self._applying_preset:
            for card in self.cards:
                card.set_selected(False)

    def run(self, title: str = "Custom run"):
        if self.running:
            return
        messages = [m for m in self.messages.get("1.0", tk.END).splitlines() if m.strip()]
        if not messages:
            self._set_banner("idle", "Type at least one message")
            return
        old, new = self.old_text.get(), self.new_text.get()
        params = dict(
            mitm=self.mitm.get(),
            sign=self.sign.get(),
            corrupt=self.corrupt.get(),
            messages=messages,
            replacements=[(old, new)] if old else [],
        )
        self._clear_log()
        self.running = True
        self.run_button.set_enabled(False)
        self._set_banner("running", f"{title} — running…")
        self._steps = self._scenario(params)
        self._advance()

    def _advance(self):
        try:
            command = next(self._steps)
        except StopIteration:
            self._finish()
            return
        except Exception as exc:  # surface it in the window instead of the terminal
            self._set_banner("attack", f"Error: {type(exc).__name__}: {exc}")
            self._finish()
            return
        if command[0] == "wait":
            self.root.after(self._ms(command[1]), self._advance)
        else:
            _, src, dst, label, color, style = command
            self._animate_hop(src, dst, label, color, style, self._advance)

    def _finish(self):
        for item in self._packet:
            self.canvas.delete(item)
        self._packet = []
        self.running = False
        self.run_button.set_enabled(True)

    def _send(self, channel: Channel, packet, src: str, dst: str, label: str, forged_label: str):
        """Animate one packet across the channel, returning what arrives."""
        middle = "MALLORY" if self.state.mitm else "MID"
        yield ("move", src, middle, label, PARTY_COLORS[src], "normal")
        was_corrupted = channel.corrupted
        delivered = channel.transmit(packet)
        self._redraw()
        if channel.corrupted and not was_corrupted:
            style, out_label = "corrupt", f"{label} · 1 bit flipped"
        elif self.state.mitm:
            style, out_label = "forged", forged_label
        else:
            style, out_label = "normal", label
        yield ("move", middle, dst, out_label, PARTY_COLORS[src], style)
        return delivered

    def _scenario(self, p: dict):
        """The protocol of demo.run, one yield per animation step."""
        mitm, sign = p["mitm"], p["sign"]
        self.state = DiagramState(mitm=mitm)
        self._redraw()
        yield ("wait", 150)

        bob = Bob()
        alice = Alice(trusted_bob_key=bob.verify_key if sign else None)
        mallory = Mallory(p["replacements"]) if mitm else None
        channel = Channel(mallory=mallory, corrupt=p["corrupt"])
        chips = self.state.chips
        chips["BOB"].append(Chip("RSA private key", PARTY_COLORS["BOB"]))
        if sign:
            chips["BOB"].append(Chip("Ed25519 signing key", PARTY_COLORS["BOB"]))
            chips["ALICE"].append(Chip("Bob's Ed25519 key (trusted)", PARTY_COLORS["BOB"]))
        if mitm:
            chips["MALLORY"].append(Chip("own RSA key pair", PARTY_COLORS["MALLORY"]))
        self._redraw()

        heading("1. Bob publishes his RSA public key")
        key_packet = bob.announce_key(sign)
        label = "RSA public key + signature" if sign else "RSA public key"
        delivered = yield from self._send(channel, key_packet, "BOB", "ALICE", label, "Mallory's RSA key")
        ok = alice.receive_key(delivered)
        owner = "MALLORY" if mitm else "BOB"
        fp = primitives.fingerprint(delivered.rsa_der)[:5]
        chips["ALICE"].append(Chip(f"RSA public key {fp}", PARTY_COLORS[owner]))
        if not ok:
            self.state.status["ALICE"] = "ABORTED — signature check failed"
            self._flash("ALICE", PARTY_COLORS["MALLORY"])
        else:
            self._redraw()
        yield ("wait", 300)

        if ok:
            heading("2. Alice sends Bob the session key")
            envelope = alice.make_envelope()
            chips["ALICE"].append(Chip("AES-256 session key", ACCENT))
            self._redraw()
            delivered = yield from self._send(channel, envelope, "ALICE", "BOB",
                                              "RSA-OAEP(AES key)", "re-wrapped AES key")
            if mitm:
                chips["MALLORY"].append(Chip("Alice's AES key (stolen)", PARTY_COLORS["MALLORY"]))
            bob.receive_envelope(delivered)
            chips["BOB"].append(Chip("AES-256 session key", ACCENT))
            self._redraw()
            yield ("wait", 300)

            heading("3. Encrypted messages")
            for i, text in enumerate(p["messages"]):
                packet = alice.send(text)
                delivered = yield from self._send(channel, packet, "ALICE", "BOB",
                                                  f"AES-GCM message #{i}", f"message #{i} re-encrypted")
                accepted = bob.receive_message(delivered)
                self.state.status["BOB"] = f"received {len(bob.received)} · rejected {bob.rejected}"
                if mitm:
                    self.state.status["MALLORY"] = f"read {len(mallory.read)} message(s)"
                self._flash("BOB", PARTY_COLORS["BOB"] if accepted else WARN)
                yield ("wait", 250)

        result = demo.Result(
            handshake_ok=ok,
            bob_received=list(bob.received),
            bob_rejected=bob.rejected,
            mallory_read=list(mallory.read) if mallory else [],
        )
        demo.summarize(result, p["messages"], mitm)
        self.last_verdict = verdict(result, mitm, p["messages"])
        self._set_banner(*self.last_verdict)

    # --- widgets ----------------------------------------------------------------------

    def _append(self, party: str | None, text: str):
        self.log.configure(state=tk.NORMAL)
        if party is None:
            self.log.insert(tk.END, f"{text}\n", "heading")
        else:
            self.log.insert(tk.END, f"{party.ljust(8)} ", party)
            alert = any(word in text for word in ("REJECTED", "ABORTED"))
            self.log.insert(tk.END, f"{text}\n", "alert" if alert else ())
        self.log.configure(state=tk.DISABLED)
        self.log.see(tk.END)

    def _clear_log(self):
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)

    def _set_banner(self, style: str, text: str):
        bg, fg = VERDICT_STYLES[style]
        self.banner.configure(text=text, bg=bg, fg=fg)

    def close(self):
        output.set_sink(None)
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
