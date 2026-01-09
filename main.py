import tkinter as tk
from tkinter import ttk
from analyzer import PasswordAnalyzer
from hibp_checker import HIBPChecker

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("900x550")
        self.root.configure(bg="#1e1e1e")

        self.analyzer = PasswordAnalyzer()
        self.hibp_checker = HIBPChecker()

        self._setup_styles()
        self._create_widgets()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background="#1e1e1e",
            foreground="white",
            fieldbackground="#1e1e1e",
            rowheight=26
        )
        style.map("Treeview", background=[("selected", "#333333")])

        style.configure("TButton", padding=6)
        style.configure("TProgressbar", thickness=20)

    def _create_widgets(self):
        # Top Input Row
        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(pady=15)

        tk.Label(top, text="Password:", fg="white", bg="#1e1e1e").pack(side="left", padx=5)

        self.password_entry = tk.Entry(
            top, width=40, bg="#2d2d2d", fg="white",
            insertbackground="white", font=("Arial", 12)
        )
        self.password_entry.pack(side="left", padx=5)

        ttk.Button(top, text="Analyze", command=self.analyze_password).pack(side="left", padx=10)

        # Summary Frame
        summary = tk.Frame(self.root, bg="#1e1e1e")
        summary.pack(pady=10, fill="x")

        self.length_label = tk.Label(summary, text="Length: -", fg="white", bg="#1e1e1e")
        self.length_label.pack(side="left", padx=20)

        self.strength_label = tk.Label(summary, text="Strength: -", fg="white", bg="#1e1e1e")
        self.strength_label.pack(side="left", padx=20)

        self.score_bar = ttk.Progressbar(summary, length=300, maximum=100)
        self.score_bar.pack(side="left", padx=20)

        # Checks Table
        table_frame = tk.Frame(self.root, bg="#1e1e1e")
        table_frame.pack(pady=10, fill="both", expand=True)

        columns = ("Check", "Status", "Details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.tag_configure("PASS", foreground="#00ff99")
        self.tree.tag_configure("FAIL", foreground="#ff5555")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=20)

        # Recommendations
        rec_frame = tk.Frame(self.root, bg="#1e1e1e")
        rec_frame.pack(pady=10, fill="x")

        tk.Label(
            rec_frame, text="Recommendations:",
            fg="white", bg="#1e1e1e"
        ).pack(anchor="w", padx=20)

        self.recommendations = tk.Listbox(
            rec_frame, height=4,
            bg="#121212", fg="#00ff99"
        )
        self.recommendations.pack(fill="x", padx=20)

        self.hibp_label = tk.Label(
            summary,
            text="HIBP: -",
            fg="white",
            bg="#1e1e1e"
        )
        self.hibp_label.pack(side="left", padx=20)


    def analyze_password(self):
        password = self.password_entry.get()

        # Manual Analyzer
        results = self.analyzer.analyze(password)

        self.length_label.config(text=f"Length: {results['password_length']}")
        self.strength_label.config(
            text=f"Strength: {results['strength']}",
            fg=self._strength_color(results['strength'])
        )
        self.score_bar["value"] = results["score"]

        # HIBP CHECK
        breached, count = self.hibp_checker.check_password(password)

        if count == -1:
            self.hibp_label.config(
                text="HIBP: ⚠ Error checking",
                fg="#ffaa00"
            )
        elif breached:
            self.hibp_label.config(
                text=f"HIBP: ❌ Breached ({count:,} times)",
                fg="#ff5555"
            )
        else:
            self.hibp_label.config(
                text="HIBP: ✅ Not found",
                fg="#00ff99"
            )

        # Checks Table
        self.tree.delete(*self.tree.get_children())
        for name, data in results["checks"].items():
            status = "PASS" if data.get("passed", True) else "FAIL"
            detail = data.get("message") or data.get("rating") or data.get("value")
            self.tree.insert(
                "",
                "end",
                values=(name.title().replace("_", " "), status, detail),
                tags=(status,)
            )

        
        self.tree_tags = {
             "PASS": {"foreground": "#00ff99"},
            "FAIL": {"foreground": "#ff5555"},
        }


        # Recommendations
        self.recommendations.delete(0, tk.END)
        for rec in results.get("recommendations", []):
            self.recommendations.insert(tk.END, f"• {rec}")


    def _strength_color(self, strength):
        return {
            "Weak": "#ff5555",
            "Medium": "#ffaa00",
            "Strong": "#00ff99"
        }.get(strength, "white")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()
