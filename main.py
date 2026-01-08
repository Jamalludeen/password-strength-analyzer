import tkinter as tk
from tkinter import ttk


class PasswordAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer App")
        self.root.geometry("400x200")
        self.root.resizable(False, False)

        # Dark mode colors
        self.BG_COLOR = "#1e1e1e"
        self.FG_COLOR = "#ffffff"
        self.ENTRY_BG = "#2d2d2d"
        self.BUTTON_BG = "#3c3c3c"

        self.root.configure(bg=self.BG_COLOR)

        self._setup_styles()
        self._create_widgets()

    def _setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "TButton",
            background=self.BUTTON_BG,
            foreground=self.FG_COLOR,
            padding=6
        )

        style.map(
            "TButton",
            background=[("active", "#505050")]
        )

    def _create_widgets(self):
        """Create and place widgets"""

        # Label
        self.label = tk.Label(
            self.root,
            text="Enter Password:",
            bg=self.BG_COLOR,
            fg=self.FG_COLOR,
            font=("Arial", 12)
        )
        self.label.pack(pady=(20, 5))

        # Entry (visible password)
        self.password_entry = tk.Entry(
            self.root,
            bg=self.ENTRY_BG,
            fg=self.FG_COLOR,
            insertbackground=self.FG_COLOR,
            font=("Arial", 12),
            width=30
        )
        self.password_entry.pack(pady=5)

        # Button
        self.button = ttk.Button(
            self.root,
            text="Check Password",
            command=self.show_password
        )
        self.button.pack(pady=10)

        # Output label at bottom
        self.output_label = tk.Label(
            self.root,
            text="",
            bg=self.BG_COLOR,
            fg="#00ff99",
            font=("Arial", 11)
        )
        self.output_label.pack(side="bottom", pady=20)

    def show_password(self):
        """Display the entered password"""
        password = self.password_entry.get()
        self.output_label.config(text=f"Entered Password: {password}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzer(root)
    root.mainloop()
