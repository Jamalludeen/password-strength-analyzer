import tkinter as tk
from tkinter import ttk
import threading

from analyzer import PasswordAnalyzer
from hibp_checker import HIBPChecker


ACCENT = "#00ffcc"
BG = "#1e1e1e"
CARD = "#252526"
TEXT = "#ffffff"
MUTED = "#aaaaaa"


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("1200x700")
        self.root.configure(bg=BG)

        self.analyzer = PasswordAnalyzer()
        self.hibp_checker = HIBPChecker()
        self.show_password = tk.BooleanVar(value=False)

        self._setup_styles()
        self._create_widgets()
        self._bind_events()

    # ---------------- STYLES ---------------- #
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background=CARD,
            foreground=TEXT,
            fieldbackground=CARD,
            rowheight=30,
            borderwidth=0
        )
        style.map("Treeview", background=[("selected", "#333333")])

        style.configure(
            "Accent.TButton",
            padding=10,
            background=ACCENT,
            foreground="black"
        )

        style.configure(
            "TProgressbar",
            thickness=18,
            troughcolor="#333333",
            background=ACCENT
        )

    # ---------------- UI ---------------- #
    def _create_widgets(self):
        # ---------- HEADER ----------
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", pady=(20, 10))

        tk.Label(
            header,
            text="🔐 Password Strength Analyzer",
            font=("Segoe UI", 20, "bold"),
            fg=TEXT,
            bg=BG
        ).pack()

        tk.Label(
            header,
            text="Analyze password strength & check breaches securely",
            font=("Segoe UI", 10),
            fg=MUTED,
            bg=BG
        ).pack()

        # ---------- INPUT CARD ----------
        input_card = self._card(self.root)
        input_card.pack(fill="x", padx=30, pady=15)

        tk.Label(
            input_card,
            text="Enter Password",
            fg=MUTED,
            bg=CARD
        ).pack(anchor="w")

        row = tk.Frame(input_card, bg=CARD)
        row.pack(fill="x", pady=10)

        self.password_entry = tk.Entry(
            row,
            font=("Segoe UI", 13),
            bg="#2d2d2d",
            fg=TEXT,
            insertbackground=TEXT,
            show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Checkbutton(
            row,
            text="Show",
            variable=self.show_password,
            command=self._toggle_password_visibility
        ).pack(side="left", padx=8)

        self.analyze_btn = ttk.Button(
            row,
            text="Analyze",
            style="Accent.TButton",
            command=self.analyze_password,
            state="disabled"
        )
        self.analyze_btn.pack(side="left")

        # ---------- SUMMARY ----------
        summary = self._card(self.root)
        summary.pack(fill="x", padx=30)

        self.length_label = tk.Label(summary, text="Length: 0", fg=TEXT, bg=CARD)
        self.length_label.pack(side="left", padx=20)

        self.strength_label = tk.Label(summary, text="Strength: -", fg=TEXT, bg=CARD)
        self.strength_label.pack(side="left", padx=20)

        self.score_bar = ttk.Progressbar(summary, length=300, maximum=100)
        self.score_bar.pack(side="left", padx=20)

        self.spinner = ttk.Progressbar(summary, mode="indeterminate", length=120)

        self.hibp_label = tk.Label(summary, text="HIBP: -", fg=TEXT, bg=CARD)
        self.hibp_label.pack(side="right", padx=20)

        # ---------- ANALYSIS ----------
        analysis = self._card(self.root)
        analysis.pack(fill="both", expand=True, padx=30, pady=15)

        columns = ("Check", "Status", "Details")
        self.tree = ttk.Treeview(analysis, columns=columns, show="headings")

        self.tree.tag_configure("PASS", foreground="#00ff99")
        self.tree.tag_configure("FAIL", foreground="#ff5555")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill="both", expand=True)

        # ---------- RECOMMENDATIONS ----------
        rec = self._card(self.root)
        rec.pack(fill="x", padx=30, pady=(0, 20))

        tk.Label(rec, text="Recommendations", fg=MUTED, bg=CARD).pack(anchor="w")

        self.recommendations = tk.Listbox(
            rec,
            height=4,
            bg="#121212",
            fg=ACCENT,
            highlightthickness=0
        )
        self.recommendations.pack(fill="x", pady=5)

    def _card(self, parent):
        return tk.Frame(parent, bg=CARD, padx=15, pady=15)

    # ---------------- EVENTS ---------------- #
    def _bind_events(self):
        self.password_entry.bind("<KeyRelease>", self._on_password_typing)
        self.root.bind("<Return>", lambda e: self.analyze_password())
        self.root.bind("<Escape>", lambda e: self._reset_ui())

    def _toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_password.get() else "•")

    def _on_password_typing(self, event):
        password = self.password_entry.get().strip()
        self.analyze_btn.config(state="normal" if password else "disabled")

        if password:
            results = self.analyzer.analyze(password)
            self.score_bar["value"] = results["score"]
            self.strength_label.config(
                text=f"Strength: {results['strength']}",
                fg=self._strength_color(results['strength'])
            )
            self.length_label.config(text=f"Length: {len(password)}")
        else:
            self._reset_ui()

    # ---------------- LOGIC ---------------- #
    def analyze_password(self):
        password = self.password_entry.get().strip()
        if not password:
            return

        self.spinner.pack(side="right", padx=10)
        self.spinner.start(10)
        self.hibp_label.config(text="HIBP: Checking...", fg="#ffaa00")

        threading.Thread(
            target=self._run_hibp_check,
            args=(password,),
            daemon=True
        ).start()

        results = self.analyzer.analyze(password)

        self.tree.delete(*self.tree.get_children())
        for name, data in results["checks"].items():
            status = "PASS" if data.get("passed", True) else "FAIL"
            icon = "✔" if status == "PASS" else "✖"
            detail = data.get("message") or data.get("rating") or data.get("value")
            self.tree.insert(
                "", "end",
                values=(name.replace("_", " ").title(), f"{icon} {status}", detail),
                tags=(status,)
            )

        self.recommendations.delete(0, tk.END)
        for rec in results["recommendations"]:
            self.recommendations.insert(tk.END, f"• {rec}")

    def _run_hibp_check(self, password):
        breached, count = self.hibp_checker.check_password(password)
        self.root.after(0, self._update_hibp_ui, breached, count)

    def _update_hibp_ui(self, breached, count):
        self.spinner.stop()
        self.spinner.pack_forget()

        if count == -1:
            self.hibp_label.config(text="HIBP: Error", fg="#ffaa00")
        elif breached:
            self.hibp_label.config(
                text=f"HIBP: Breached ({count:,})",
                fg="#ff5555"
            )
        else:
            self.hibp_label.config(text="HIBP: Safe", fg="#00ff99")

    def _reset_ui(self):
        self.score_bar["value"] = 0
        self.length_label.config(text="Length: 0")
        self.strength_label.config(text="Strength: -", fg=TEXT)
        self.hibp_label.config(text="HIBP: -", fg=TEXT)
        self.spinner.stop()
        self.spinner.pack_forget()
        self.tree.delete(*self.tree.get_children())
        self.recommendations.delete(0, tk.END)

    def _strength_color(self, strength):
        return {
            "Very Weak": "#ff4444",
            "Weak": "#ff5555",
            "Moderate": "#ffaa00",
            "Strong": "#00ff99",
            "Very Strong": "#00ffaa"
        }.get(strength, TEXT)


if __name__ == "__main__":
    root = tk.Tk()
    PasswordAnalyzerApp(root)
    root.mainloop()
