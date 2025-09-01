"""
Simple GUI for the packet sniffer.

Features:
- Start / Stop the sniffer (runs sniffer.py as a subprocess)
- Live output streaming into a scrollable text area
- Simple text filter, Clear and Save log buttons

Usage: run this script with the same Python interpreter you used to run
`sniffer.py` (run as Administrator/root if you need raw socket privileges).
"""
import os
import sys
import subprocess
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


class SnifferUI(tk.Tk):
    """Main GUI application."""

    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer - UI")
        self.geometry("800x500")

        # Path to sniffer.py next to this file
        self.sniffer_path = os.path.join(
            os.path.dirname(__file__), "sniffer.py"
        )

        # Process and thread control
        self.proc = None
        self.thread = None
        self.stop_event = threading.Event()
        self.stdout_queue = queue.Queue()

        self._build_ui()

    def _build_ui(self):
        # Top controls frame
        frm = ttk.Frame(self)
        frm.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        self.start_btn = ttk.Button(
            frm, text="Start", command=self.start_sniffer
        )
        self.start_btn.pack(side=tk.LEFT)

        self.stop_btn = ttk.Button(frm, text="Stop", command=self.stop_sniffer)
        self.stop_btn.pack(side=tk.LEFT, padx=(6, 0))
        self.stop_btn.state(["disabled"])

        ttk.Button(
            frm, text="Clear", command=self.clear_text
        ).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm, text="Save", command=self.save_log).pack(side=tk.LEFT)

        ttk.Label(frm, text="Filter:").pack(side=tk.LEFT, padx=(12, 4))
        self.filter_var = tk.StringVar()
        ttk.Entry(
            frm, textvariable=self.filter_var, width=20
        ).pack(side=tk.LEFT)

        # Text output with scrollbar
        txt_frame = ttk.Frame(self)
        txt_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.text = tk.Text(txt_frame, wrap=tk.NONE)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ysb = ttk.Scrollbar(
            txt_frame, orient=tk.VERTICAL, command=self.text.yview
        )
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.configure(yscrollcommand=ysb.set)

        # Poll queue periodically to update UI
        self.after(100, self._poll_stdout)

    def start_sniffer(self):
        """Start sniffer.py as a subprocess and begin reading its stdout."""
        if not os.path.exists(self.sniffer_path):
            messagebox.showerror(
                "Error", f"sniffer.py not found at {self.sniffer_path}"
            )
            return

        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Info", "Sniffer is already running")
            return

        # Build command using the same Python interpreter
        cmd = [sys.executable, self.sniffer_path]

        try:
            # Start subprocess and capture stdout/stderr
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as exc:
            messagebox.showerror("Failed to start", str(exc))
            return

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._reader_thread, daemon=True
        )
        self.thread.start()

        self.start_btn.state(["disabled"])
        # enable stop button
        self.stop_btn.state(["!disabled"])  # enable stop

    def stop_sniffer(self):
        """Stop the subprocess and signal the reader thread to finish."""
        if not self.proc:
            return
        try:
            # Terminate gracefully
            self.proc.terminate()
        except Exception:
            pass

        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

        self.proc = None
        self.start_btn.state(["!disabled"])
        self.stop_btn.state(["disabled"])

    def _reader_thread(self):
        """Read process stdout line-by-line and push into a queue
        for the GUI thread.
        """
        try:
            for line in self.proc.stdout:
                if line is None:
                    break
                self.stdout_queue.put(line)
                if self.stop_event.is_set():
                    break
        except Exception:
            pass

    def _poll_stdout(self):
        """Poll the stdout queue and insert lines into the text widget
        with optional filtering.
        """
        try:
            while True:
                line = self.stdout_queue.get_nowait()
                flt = self.filter_var.get().strip()
                if flt:
                    if flt.lower() in line.lower():
                        self._append_text(line)
                else:
                    self._append_text(line)
        except queue.Empty:
            pass

        # If process ended, update buttons
        if self.proc and self.proc.poll() is not None:
            # process finished
            self.proc = None
            self.start_btn.state(["!disabled"])
            self.stop_btn.state(["disabled"])

        self.after(100, self._poll_stdout)

    def _append_text(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def clear_text(self):
        self.text.delete("1.0", tk.END)

    def save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[
                ("Log files", "*.log"), ("Text files", "*.txt"),
                ("All files", "*")
            ],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.text.get("1.0", tk.END))


if __name__ == "__main__":
    app = SnifferUI()
    app.mainloop()
