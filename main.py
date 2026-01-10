import tkinter as tk
from tkinter import ttk
import threading

from analyzer import PasswordAnalyzer
from hibp_checker import HIBPChecker


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("1200x650")
        self.root.configure(bg="#1e1e1e")

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
            background="#1e1e1e",
            foreground="white",
            fieldbackground="#1e1e1e",
            rowheight=28
        )
        style.map("Treeview", background=[("selected", "#333333")])

        style.configure("TButton", padding=8)
        style.configure("TProgressbar", thickness=18)

    # ---------------- UI ---------------- #
    def _create_widgets(self):
        # ---------- INPUT ----------
        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(pady=20)

        tk.Label(top, text="Password:", fg="white", bg="#1e1e1e").pack(side="left", padx=5)

        self.password_entry = tk.Entry(
            top,
            width=42,
            bg="#2d2d2d",
            fg="white",
            insertbackground="white",
            font=("Arial", 12),
            show="•"
        )
        self.password_entry.pack(side="left", padx=5)

        ttk.Checkbutton(
            top,
            text="Show",
            variable=self.show_password,
            command=self._toggle_password_visibility
        ).pack(side="left", padx=8)

        self.analyze_btn = ttk.Button(
            top,
            text="Analyze",
            command=self.analyze_password,
            state="disabled"
        )
        self.analyze_btn.pack(side="left", padx=10)

        # ---------- SUMMARY ----------
        summary = tk.LabelFrame(
            self.root,
            text=" Summary ",
            bg="#1e1e1e",
            fg="#aaaaaa",
            padx=10,
            pady=10
        )
        summary.pack(fill="x", padx=20)

        self.length_label = tk.Label(summary, text="Length: 0", fg="white", bg="#1e1e1e")
        self.length_label.pack(side="left", padx=20)

        self.strength_label = tk.Label(summary, text="Strength: -", fg="white", bg="#1e1e1e")
        self.strength_label.pack(side="left", padx=20)

        self.score_bar = ttk.Progressbar(summary, length=300, maximum=100)
        self.score_bar.pack(side="left", padx=20)

        self.spinner = ttk.Progressbar(summary, mode="indeterminate", length=120)
        self.spinner.stop()

        self.hibp_label = tk.Label(summary, text="HIBP: -", fg="white", bg="#1e1e1e")
        self.hibp_label.pack(side="left", padx=20)

        # ---------- TABLE ----------
        table_frame = tk.LabelFrame(
            self.root,
            text=" Checks ",
            bg="#1e1e1e",
            fg="#aaaaaa"
        )
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)

        columns = ("Check", "Status", "Details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.tag_configure("PASS", foreground="#00ff99")
        self.tree.tag_configure("FAIL", foreground="#ff5555")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill="both", expand=True)

        # ---------- RECOMMENDATIONS ----------
        rec_frame = tk.LabelFrame(
            self.root,
            text=" Recommendations ",
            bg="#1e1e1e",
            fg="#aaaaaa"
        )
        rec_frame.pack(fill="x", padx=20, pady=10)

        self.recommendations = tk.Listbox(
            rec_frame,
            height=4,
            bg="#121212",
            fg="#00ff99",
            highlightthickness=0
        )
        self.recommendations.pack(fill="x", padx=10, pady=5)

    # ---------------- EVENTS ---------------- #
    def _bind_events(self):
        self.password_entry.bind("<KeyRelease>", self._on_password_typing)
        self.root.bind("<Return>", lambda e: self.analyze_password())
        self.root.bind("<Escape>", lambda e: self._reset_ui_for_empty_password())

    def _toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_password.get() else "•")

    def _on_password_typing(self, event):
        password = self.password_entry.get().strip()

        self.analyze_btn.config(
            state="normal" if password else "disabled"
        )

        if password:
            results = self.analyzer.analyze(password)
            self.score_bar["value"] = results["score"]
            self.strength_label.config(
                text=f"Strength: {results['strength']}",
                fg=self._strength_color(results['strength'])
            )
            self.length_label.config(text=f"Length: {len(password)}")
        else:
            self._reset_ui_for_empty_password()

    # ---------------- LOGIC ---------------- #
    def analyze_password(self):
        password = self.password_entry.get().strip()
        if not password:
            return

        self.spinner.pack(side="left", padx=10)
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
            detail = data.get("message") or data.get("rating") or data.get("value")
            self.tree.insert(
                "", "end",
                values=(name.replace("_", " ").title(), status, detail),
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
                text=f"HIBP: ❌ Breached ({count:,})",
                fg="#ff5555"
            )
        else:
            self.hibp_label.config(text="HIBP: ✅ Safe", fg="#00ff99")

    def _reset_ui_for_empty_password(self):
        self.score_bar["value"] = 0
        self.length_label.config(text="Length: 0")
        self.strength_label.config(text="Strength: -", fg="white")
        self.hibp_label.config(text="HIBP: -", fg="white")
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
        }.get(strength, "white")


if __name__ == "__main__":
    root = tk.Tk()
    PasswordAnalyzerApp(root)
    root.mainloop()
