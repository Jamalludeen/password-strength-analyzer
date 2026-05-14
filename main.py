import threading
import tkinter as tk
from tkinter import ttk

from analyzer import PasswordAnalyzer
from hibp_checker import HIBPChecker
from password_generator import GeneratorOptions, PasswordGenerator


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("1200x780")
        self.root.configure(bg="#121826")

        self.colors = {
            "bg": "#121826",
            "panel": "#172033",
            "panel_alt": "#1f2a42",
            "text": "#f5f7fb",
            "muted": "#a9b4c7",
            "accent": "#7dd3fc",
            "accent_alt": "#38bdf8",
            "success": "#34d399",
            "warning": "#fbbf24",
            "danger": "#fb7185",
            "field": "#0f172a",
        }

        self.analyzer = PasswordAnalyzer()
        self.hibp_checker = HIBPChecker()
        self.password_generator = PasswordGenerator()

        self.show_password = tk.BooleanVar(value=False)
        self.is_checking_hibp = False
        self.current_password = ""
        self.current_results = None
        self.recent_analyses = []
        self.last_summary_text = ""
        self.analysis_count = 0

        self.generated_passwords = []
        self.generated_results = []
        self.generator_length = tk.IntVar(value=16)
        self.generator_count = tk.IntVar(value=5)
        self.generator_use_lowercase = tk.BooleanVar(value=True)
        self.generator_use_uppercase = tk.BooleanVar(value=True)
        self.generator_use_digits = tk.BooleanVar(value=True)
        self.generator_use_symbols = tk.BooleanVar(value=True)
        self.generator_avoid_ambiguous = tk.BooleanVar(value=False)
        self.generator_require_each = tk.BooleanVar(value=True)

        self._setup_styles()
        self._create_widgets()
        self._bind_events()

    # ---------------- STYLES ---------------- #
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background=self.colors["panel"],
            foreground=self.colors["text"],
            fieldbackground=self.colors["panel"],
            rowheight=28,
        )
        style.map("Treeview", background=[("selected", self.colors["panel_alt"])])

        style.configure("TButton", padding=8)
        style.configure("TProgressbar", thickness=18)
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            padding=(16, 8),
            background=self.colors["panel"],
            foreground=self.colors["muted"],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["panel_alt"])],
            foreground=[("selected", self.colors["text"])],
        )

    def _configure_panel(self, widget):
        widget.configure(bg=self.colors["panel"])

    def _configure_label(self, widget, color=None):
        widget.configure(bg=self.colors["panel"], fg=color or self.colors["text"])

    # ---------------- UI ---------------- #
    def _create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.analyzer_tab = tk.Frame(self.notebook, bg="#1e1e1e")
        self.generator_tab = tk.Frame(self.notebook, bg="#1e1e1e")

        self.notebook.add(self.analyzer_tab, text="Analyzer")
        self.notebook.add(self.generator_tab, text="Generator")

        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            anchor="w",
            padx=14,
            pady=8,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
        )
        self.status_bar.pack(fill="x", side="bottom")

        self._create_analyzer_tab()
        self._create_generator_tab()

    def _set_status(self, text, color=None):
        self.status_bar.config(text=text, fg=color or self.colors["muted"])

    def _create_analyzer_tab(self):
        top = tk.Frame(self.analyzer_tab, bg=self.colors["bg"])
        top.pack(pady=(18, 10), padx=20, fill="x")

        tk.Label(top, text="Password:", fg=self.colors["muted"], bg=self.colors["bg"], font=("Arial", 11, "bold")).pack(side="left", padx=(4, 8))

        self.password_entry = tk.Entry(
            top,
            width=42,
            bg="#2d2d2d",
            fg="white",
            insertbackground="white",
            font=("Arial", 12),
            show="•",
        )
        self.password_entry.pack(side="left", padx=5)

        ttk.Checkbutton(
            top,
            text="Show",
            variable=self.show_password,
            command=self._toggle_password_visibility,
        ).pack(side="left", padx=(8, 12))

        self.analyze_btn = ttk.Button(top, text="Analyze", command=self.analyze_password, state="disabled")
        self.analyze_btn.pack(side="left", padx=(0, 8))

        self.copy_summary_btn = ttk.Button(
            top,
            text="Copy Summary",
            command=self._copy_summary_to_clipboard,
            state="disabled",
        )
        self.copy_summary_btn.pack(side="left", padx=(0, 8))

        self.clear_history_btn = ttk.Button(top, text="Clear History", command=self._clear_history)
        self.clear_history_btn.pack(side="left", padx=(0, 8))

        summary = tk.LabelFrame(
            self.analyzer_tab,
            text=" Summary ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            padx=10,
            pady=10,
        )
        summary.pack(fill="x", padx=20, pady=(0, 10))

        self.length_label = tk.Label(summary, text="Length: 0", fg=self.colors["text"], bg=self.colors["panel"])
        self.length_label.pack(side="left", padx=(8, 18))

        self.strength_label = tk.Label(summary, text="Strength: -", fg=self.colors["text"], bg=self.colors["panel"])
        self.strength_label.pack(side="left", padx=(0, 18))

        self.analysis_count_label = tk.Label(summary, text="Analyses: 0", fg=self.colors["text"], bg=self.colors["panel"])
        self.analysis_count_label.pack(side="left", padx=(0, 18))

        self.score_bar = ttk.Progressbar(summary, length=300, maximum=100)
        self.score_bar.pack(side="left", padx=(0, 18))

        self.spinner = ttk.Progressbar(summary, mode="indeterminate", length=120)
        self.spinner.stop()

        self.hibp_label = tk.Label(summary, text="HIBP: -", fg=self.colors["text"], bg=self.colors["panel"])
        self.hibp_label.pack(side="left", padx=(0, 18))

        self.summary_hint_label = tk.Label(summary, text="Ready", fg=self.colors["muted"], bg=self.colors["panel"])
        self.summary_hint_label.pack(side="left", padx=20)

        table_frame = tk.LabelFrame(self.analyzer_tab, text=" Checks ", bg=self.colors["panel"], fg=self.colors["muted"])
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        columns = ("Check", "Status", "Details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.tag_configure("PASS", foreground="#00ff99")
        self.tree.tag_configure("FAIL", foreground="#ff5555")
        self.tree.tag_configure("row_even", background=self.colors["panel"])
        self.tree.tag_configure("row_odd", background=self.colors["panel_alt"])

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")
            self.tree.heading(col, text=col.upper())

        self.tree.column("Check", width=220)
        self.tree.column("Status", width=110)
        self.tree.column("Details", width=420)

        self.tree.pack(fill="both", expand=True)

        rec_frame = tk.LabelFrame(
            self.analyzer_tab,
            text=" Recommendations ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
        )
        rec_frame.pack(fill="x", padx=20, pady=(0, 10))

        self.recommendations = tk.Listbox(
            rec_frame,
            height=4,
            bg=self.colors["field"],
            fg=self.colors["success"],
            highlightthickness=0,
        )
        self.recommendations.pack(fill="x", padx=10, pady=5)

        history_frame = tk.LabelFrame(
            self.analyzer_tab,
            text=" Recent Analyses ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
        )
        history_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.history_listbox = tk.Listbox(
            history_frame,
            height=6,
            bg=self.colors["field"],
            fg=self.colors["text"],
            highlightthickness=0,
        )
        self.history_listbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.history_listbox.bind("<Double-Button-1>", self._copy_selected_history_entry)

    def _create_generator_tab(self):
        options_frame = tk.LabelFrame(
            self.generator_tab,
            text=" Generator Options ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            padx=10,
            pady=10,
        )
        options_frame.pack(fill="x", padx=20, pady=(18, 10))

        tk.Label(options_frame, text="Length:", fg=self.colors["text"], bg=self.colors["panel"], font=("Arial", 10, "bold")).grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.length_spinbox = tk.Spinbox(
            options_frame,
            from_=4,
            to=128,
            textvariable=self.generator_length,
            width=8,
            bg=self.colors["field"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.length_spinbox.grid(row=0, column=1, padx=8, pady=6, sticky="w")

        tk.Label(options_frame, text="Batch:", fg=self.colors["text"], bg=self.colors["panel"], font=("Arial", 10, "bold")).grid(row=0, column=2, padx=8, pady=6, sticky="w")
        self.count_spinbox = tk.Spinbox(
            options_frame,
            from_=1,
            to=10,
            textvariable=self.generator_count,
            width=8,
            bg=self.colors["field"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.count_spinbox.grid(row=0, column=3, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Lowercase",
            variable=self.generator_use_lowercase,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=1, column=0, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Uppercase",
            variable=self.generator_use_uppercase,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=1, column=1, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Digits",
            variable=self.generator_use_digits,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=1, column=2, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Symbols",
            variable=self.generator_use_symbols,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=1, column=3, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Avoid ambiguous chars (0/O/1/l/I)",
            variable=self.generator_avoid_ambiguous,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=2, column=0, columnspan=2, padx=8, pady=6, sticky="w")

        tk.Checkbutton(
            options_frame,
            text="Require each selected character set",
            variable=self.generator_require_each,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            selectcolor=self.colors["field"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
        ).grid(row=2, column=2, columnspan=2, padx=8, pady=6, sticky="w")

        actions = tk.LabelFrame(
            self.generator_tab,
            text=" Quick Actions ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            padx=10,
            pady=10,
        )
        actions.pack(fill="x", padx=20, pady=(0, 10))

        ttk.Button(actions, text="Generate", command=self._generate_passwords).pack(side="left", padx=6)
        ttk.Button(actions, text="Copy Selected", command=self._copy_selected_generated).pack(side="left", padx=6)
        ttk.Button(actions, text="Copy Strongest", command=self._copy_strongest_generated).pack(side="left", padx=6)
        ttk.Button(actions, text="Copy Batch", command=self._copy_batch_summary).pack(side="left", padx=6)
        ttk.Button(actions, text="Analyze Selected", command=self._analyze_selected_generated).pack(side="left", padx=6)
        ttk.Button(actions, text="Remove Selected", command=self._remove_selected_generated).pack(side="left", padx=6)
        ttk.Button(actions, text="Clear", command=self._clear_generated_passwords).pack(side="left", padx=6)

        self.generator_status = tk.Label(
            actions,
            text="Tip: Select options and generate candidates.",
            fg=self.colors["muted"],
            bg=self.colors["panel"],
        )
        self.generator_status.pack(side="right", padx=6)

        generated_frame = tk.LabelFrame(
            self.generator_tab,
            text=" Generated Candidates ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
        )
        generated_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.generated_listbox = tk.Listbox(
            generated_frame,
            height=12,
            bg=self.colors["field"],
            fg=self.colors["text"],
            highlightthickness=0,
        )
        self.generated_listbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.generated_listbox.bind("<<ListboxSelect>>", self._on_generated_select)

        self.generated_detail_label = tk.Label(
            self.generator_tab,
            text="Selected: -",
            fg=self.colors["success"],
            bg=self.colors["bg"],
            anchor="w",
        )
        self.generated_detail_label.pack(fill="x", padx=20, pady=(0, 15))

        summary_frame = tk.LabelFrame(
            self.generator_tab,
            text=" Batch Summary ",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            padx=10,
            pady=10,
        )
        summary_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.generator_batch_label = tk.Label(
            summary_frame,
            text="Average score: - | Strongest: -",
            fg="white",
            bg="#1e1e1e",
            anchor="w",
        )
        self.generator_batch_label.pack(fill="x")
        self.generator_batch_summary_text = ""

    # ---------------- EVENTS ---------------- #
    def _bind_events(self):
        self.password_entry.bind("<KeyRelease>", self._on_password_typing)
        self.root.bind("<Return>", self._on_enter_key)
        self.root.bind("<Escape>", lambda e: self._reset_ui_for_empty_password())

    def _on_enter_key(self, event):
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:
            self.analyze_password()
        else:
            self._generate_passwords()

    def _toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_password.get() else "•")

    def _on_password_typing(self, event):
        password = self.password_entry.get().strip()

        self.analyze_btn.config(state="normal" if password and not self.is_checking_hibp else "disabled")

        if password:
            results = self.analyzer.analyze(password)
            self.score_bar["value"] = results["score"]
            self.strength_label.config(text=f"Strength: {results['strength']}", fg=self._strength_color(results["strength"]))
            self.length_label.config(text=f"Length: {len(password)}")
        else:
            self._reset_ui_for_empty_password()

    # ---------------- LOGIC ---------------- #
    def analyze_password(self):
        password = self.password_entry.get().strip()
        if not password:
            return

        self.is_checking_hibp = True
        self.analyze_btn.config(state="disabled")
        self.spinner.pack(side="left", padx=10)
        self.spinner.start(10)
        self.hibp_label.config(text="HIBP: Checking...", fg="#ffaa00")

        self.current_password = password
        self.current_results = self.analyzer.analyze(password)
        self.analysis_count += 1
        self.analysis_count_label.config(text=f"Analyses: {self.analysis_count}")
        self.last_summary_text = self._format_summary_text(self.current_results, "HIBP: Checking...")
        self.copy_summary_btn.config(state="normal")

        threading.Thread(target=self._run_hibp_check, args=(password,), daemon=True).start()

        results = self.current_results

        self.tree.delete(*self.tree.get_children())
        for name, data in results["checks"].items():
            status = "PASS" if data.get("passed", True) else "FAIL"
            detail = data.get("message") or data.get("rating") or data.get("value")
            self.tree.insert(
                "",
                "end",
                values=(name.replace("_", " ").title(), status, detail),
                tags=(status,),
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
        self.is_checking_hibp = False

        hibp_summary = "HIBP: Error"
        if count == -1:
            self.hibp_label.config(text="HIBP: Error", fg="#ffaa00")
        elif breached:
            hibp_summary = f"HIBP: Breached ({count:,})"
            self.hibp_label.config(text=f"HIBP: ❌ Breached ({count:,})", fg="#ff5555")
        else:
            hibp_summary = "HIBP: Safe"
            self.hibp_label.config(text="HIBP: ✅ Safe", fg="#00ff99")

        if self.current_results:
            self.last_summary_text = self._format_summary_text(self.current_results, hibp_summary)
            self._append_history_entry(hibp_summary)

        if self.password_entry.get().strip():
            self.analyze_btn.config(state="normal")
        else:
            self.analyze_btn.config(state="disabled")

    def _append_history_entry(self, hibp_summary):
        if not self.current_results:
            return

        entry = (
            f"{self.current_results['masked_password']} | "
            f"Score {self.current_results['score']}/100 | "
            f"{self.current_results['strength']} | {hibp_summary}"
        )

        self.recent_analyses.insert(0, entry)
        self.recent_analyses = self.recent_analyses[:10]
        self._refresh_history_listbox()

    def _refresh_history_listbox(self):
        self.history_listbox.delete(0, tk.END)
        for entry in self.recent_analyses:
            self.history_listbox.insert(tk.END, entry)

    def _copy_selected_history_entry(self, event):
        selected = self.history_listbox.curselection()
        if not selected:
            return

        entry = self.history_listbox.get(selected[0])
        self.root.clipboard_clear()
        self.root.clipboard_append(entry)
        self.root.update()
        self._set_status("Copied history entry", self.colors["success"])

    def _copy_summary_to_clipboard(self):
        if not self.last_summary_text:
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_summary_text)
        self.root.update()
        self._set_status("Copied analyzer summary", self.colors["success"])

    def _clear_history(self):
        self.recent_analyses.clear()
        self._refresh_history_listbox()
        self.summary_hint_label.config(text="History cleared", fg="#aaaaaa")
        self._set_status("History cleared", self.colors["muted"])

    def _format_summary_text(self, results, hibp_summary):
        return (
            f"Password: {results['masked_password']} | "
            f"Score: {results['score']}/100 | "
            f"Strength: {results['strength']} | "
            f"Length: {results['password_length']} | "
            f"{hibp_summary}"
        )

    # ---------------- GENERATOR ---------------- #
    def _generator_options(self) -> GeneratorOptions:
        try:
            length = int(self.generator_length.get())
        except (TypeError, ValueError):
            raise ValueError("Length must be a valid number")

        return GeneratorOptions(
            length=length,
            use_lowercase=self.generator_use_lowercase.get(),
            use_uppercase=self.generator_use_uppercase.get(),
            use_digits=self.generator_use_digits.get(),
            use_symbols=self.generator_use_symbols.get(),
            avoid_ambiguous=self.generator_avoid_ambiguous.get(),
            require_each_selected=self.generator_require_each.get(),
        )

    def _generate_passwords(self):
        try:
            options = self._generator_options()
            batch_size = self.generator_count.get()
            self.generated_passwords = self.password_generator.generate_many(options, count=batch_size)
        except ValueError as exc:
            self.generator_status.config(text=f"Error: {exc}", fg="#ff5555")
            return

        self.generated_listbox.delete(0, tk.END)
        self.generated_results = []
        for index, pwd in enumerate(self.generated_passwords, start=1):
            result = self.analyzer.analyze(pwd)
            self.generated_results.append(result)
            line = f"{index}. {pwd} | Score {result['score']}/100 | {result['strength']}"
            self.generated_listbox.insert(tk.END, line)

        self.generated_detail_label.config(text="Selected: -", fg="#00ff99")
        self._update_generator_batch_summary()
        if self.generated_results:
            strongest_result = max(self.generated_results, key=lambda result: result["score"])
            strongest_index = self.generated_results.index(strongest_result)
            self.generated_listbox.selection_clear(0, tk.END)
            self.generated_listbox.selection_set(strongest_index)
            self.generated_listbox.activate(strongest_index)
            self.generated_listbox.see(strongest_index)
            self._on_generated_select(None)
        self.generator_status.config(text=f"Generated {len(self.generated_passwords)} password candidates.", fg="#00ff99")
        self._set_status(f"Generated {len(self.generated_passwords)} candidates", self.colors["success"])

    def _selected_generated_password(self):
        selected = self.generated_listbox.curselection()
        if not selected:
            return None
        return self.generated_passwords[selected[0]]

    def _on_generated_select(self, event):
        pwd = self._selected_generated_password()
        if not pwd:
            self.generated_detail_label.config(text="Selected: -", fg="#00ff99")
            return

        result = self.analyzer.analyze(pwd)
        self.generated_detail_label.config(
            text=f"Selected score: {result['score']}/100 | Strength: {result['strength']} | Length: {len(pwd)}",
            fg=self._strength_color(result["strength"]),
        )

    def _copy_selected_generated(self):
        pwd = self._selected_generated_password()
        if not pwd:
            self.generator_status.config(text="Generate or select a password first.", fg="#ffaa00")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self.root.update()
        self.generator_status.config(text="Copied selected password.", fg="#00ff99")
        self._set_status("Copied selected generated password", self.colors["success"])

    def _copy_strongest_generated(self):
        if not self.generated_results:
            self.generator_status.config(text="Generate passwords first, then use Copy Strongest.", fg="#ffaa00")
            return

        strongest_result = max(self.generated_results, key=lambda result: result["score"])
        strongest_password = strongest_result["masked_password"]

        if not self.generated_passwords:
            self.generator_status.config(text="Generate passwords first, then use Copy Strongest.", fg="#ffaa00")
            return

        strongest_index = self.generated_results.index(strongest_result)
        strongest_password = self.generated_passwords[strongest_index]

        self.root.clipboard_clear()
        self.root.clipboard_append(strongest_password)
        self.root.update()
        self.generator_status.config(text="Copied strongest generated password.", fg="#00ff99")
        self._set_status("Copied strongest generated password", self.colors["success"])

    def _analyze_selected_generated(self):
        pwd = self._selected_generated_password()
        if not pwd:
            self.generator_status.config(text="Pick a generated password first.", fg="#ffaa00")
            return

        self.notebook.select(self.analyzer_tab)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd)
        self.analyze_password()
        self.generator_status.config(text="Sent selected password to Analyzer tab.", fg="#00ff99")
        self._set_status("Sent selected password to Analyzer tab", self.colors["accent"])

    def _clear_generated_passwords(self):
        self.generated_passwords = []
        self.generated_results = []
        self.generated_listbox.delete(0, tk.END)
        self.generated_detail_label.config(text="Selected: -", fg="#00ff99")
        self.generator_batch_label.config(text="Average score: - | Strongest: -")
        self.generator_status.config(text="Cleared generated passwords.", fg="#aaaaaa")
        self._set_status("Cleared generated passwords", self.colors["muted"])

    def _update_generator_batch_summary(self):
        if not self.generated_results:
            self.generator_batch_label.config(text="Average score: - | Strongest: - | Count: 0")
            return

        average_score = sum(result["score"] for result in self.generated_results) / len(self.generated_results)
        strongest_result = max(self.generated_results, key=lambda result: result["score"])
        strongest_summary = f"{strongest_result['strength']} ({strongest_result['score']}/100)"

        self.generator_batch_label.config(
            text=f"Average score: {average_score:.1f}/100 | Strongest: {strongest_summary} | Count: {len(self.generated_results)}"
        )
        self.generator_batch_summary_text = self.generator_batch_label.cget("text")

    def _copy_batch_summary(self):
        if not self.generator_batch_summary_text:
            self.generator_status.config(text="Generate passwords first, then copy the summary.", fg="#ffaa00")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.generator_batch_summary_text)
        self.root.update()
        self.generator_status.config(text="Copied batch summary.", fg="#00ff99")
        self._set_status("Copied batch summary", self.colors["success"])

    def _remove_selected_generated(self):
        selected = self.generated_listbox.curselection()
        if not selected:
            self.generator_status.config(text="Pick a generated password first.", fg="#ffaa00")
            return

        index = selected[0]
        if index >= len(self.generated_passwords):
            return

        self.generated_passwords.pop(index)
        if index < len(self.generated_results):
            self.generated_results.pop(index)

        self.generated_listbox.delete(index)
        self._update_generator_batch_summary()

        if self.generated_passwords:
            new_index = min(index, len(self.generated_passwords) - 1)
            self.generated_listbox.selection_set(new_index)
            self.generated_listbox.activate(new_index)
            self.generated_listbox.see(new_index)
            self._on_generated_select(None)
        else:
            self.generated_detail_label.config(text="Selected: -", fg="#00ff99")

        self.generator_status.config(text="Removed selected password.", fg="#00ff99")
        self._set_status("Removed selected password", self.colors["warning"])

    def _reset_ui_for_empty_password(self):
        self.score_bar["value"] = 0
        self.length_label.config(text="Length: 0")
        self.strength_label.config(text="Strength: -", fg="white")
        self.hibp_label.config(text="HIBP: -", fg="white")
        self.spinner.stop()
        self.spinner.pack_forget()
        self.tree.delete(*self.tree.get_children())
        self.recommendations.delete(0, tk.END)
        self.copy_summary_btn.config(state="disabled")
        self.last_summary_text = ""
        self.current_results = None
        self.current_password = ""
        self.is_checking_hibp = False
        self._set_status("Analyzer cleared", self.colors["muted"])

    def _strength_color(self, strength):
        return {
            "Very Weak": "#ff4444",
            "Weak": "#ff5555",
            "Moderate": "#ffaa00",
            "Strong": "#00ff99",
            "Very Strong": "#00ffaa",
        }.get(strength, "white")


if __name__ == "__main__":
    root = tk.Tk()
    PasswordAnalyzerApp(root)
    root.mainloop()
