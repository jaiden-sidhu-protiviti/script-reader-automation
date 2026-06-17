# main.py
# Main GUI and pipeline controller for the Zip Audit report builder.
# Detects host folders, determines whether they contain Linux or Windows output,
# normalizes the data via parsers, and generates JSON and HTML reports.

import os
import re
import json
import sys
import uuid
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from linuxParser import build_linux_output
from windowsParser import build_windows_output
import linuxReport
from linuxReport import load_key_vars_linux
import windowsReport
from windowsReport import load_key_vars_windows

MAX_FOLDERS = 6


def get_base_dir():
    """Always write output next to the .exe or script, not in a temp folder."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# this makes output land next to the script or the generated exe
def slugify(value):
    value = value.strip()
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value.strip("_") or "host"


def detect_os_type(folder):
    files_in_folder = os.listdir(folder)
    if "00_Analysis.txt" in files_in_folder:
        return "windows"
    if "summary.csv" in files_in_folder:
        return "linux"
    return None


# if the marker files change, this is the place to update
# the simple OS detection logic for host output folders.
def run_pipeline(sample_folders, progress_callback=None):
    # store outputs beside the running script or packaged exe
    base_dir = get_base_dir()
    output_json = os.path.join(base_dir, "output_json")
    reports_dir = os.path.join(base_dir, "reports")
    shared_report_session = str(uuid.uuid4())

    # make sure the output folders exist before we write anything
    os.makedirs(output_json, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    site_reports = []
    hosts_meta = []

    for i, folder in enumerate(sample_folders):
        if progress_callback:
            progress_callback(f"Detecting OS for: {os.path.basename(folder)}...")

        os_type = detect_os_type(folder)

        if os_type is None:
            if progress_callback:
                progress_callback(
                    f"WARNING: Could not detect OS for '{os.path.basename(folder)}' — skipping."
                )
            continue

        folder_name = os.path.basename(folder)
        temp_json_path = os.path.join(output_json, f"{folder_name}_temp_output.json")

        if os_type == "windows":
            if progress_callback:
                progress_callback(f"Parsing Windows data: {folder_name}...")

            # parse the Windows evidence files and save a temp normalized JSON output
            data = build_windows_output(folder, temp_json_path)
            key_vars = load_key_vars_windows(data)
            hostname = data.get("systeminfo", {}).get("Host Name") or "Unknown Host"
            slug = slugify(hostname)
            json_path = os.path.join(output_json, f"windows_output_{slug}.json")
            report_path = os.path.join(reports_dir, f"report_{slug}.html")
            report_module = windowsReport

        else:
            if progress_callback:
                progress_callback(f"Parsing Linux data: {folder_name}...")

            # parse the Linux evidence files and save a temp normalized JSON output
            data = build_linux_output(folder, temp_json_path)
            key_vars = load_key_vars_linux(data)
            hostname = (
                data.get("summary", {}).get("Host")
                or data.get("uname", {}).get("host")
                or "Unknown Host"
            )
            slug = slugify(hostname)
            json_path = os.path.join(output_json, f"linux_output_{slug}.json")
            report_path = os.path.join(reports_dir, f"report_{slug}.html")
            report_module = linuxReport

        # keep the temp file if it was created, then rename it to the final host-specific filename
        if temp_json_path != json_path and os.path.exists(temp_json_path):
            os.replace(temp_json_path, json_path)

        hosts_meta.append(
            {
                "folder": folder,
                "hostname": hostname,
                "slug": slug,
                "json_path": json_path,
                "report_path": report_path,
                "report_module": report_module,
                "key_vars": key_vars,
            }
        )

    # build an HTML report for each host and create next/prev navigation links
    for idx, meta in enumerate(hosts_meta):
        if progress_callback:
            progress_callback(f"Building report: {meta['hostname']}...")

        nav_links = {
            "home": os.path.join(base_dir, "index.html"),
            "prev": (
                os.path.basename(hosts_meta[idx - 1]["report_path"])
                if idx > 0
                else None
            ),
            "next": (
                os.path.basename(hosts_meta[idx + 1]["report_path"])
                if idx < len(hosts_meta) - 1
                else None
            ),
        }

        result = meta["report_module"].build_report(
            json_path=meta["json_path"],
            output_path=meta["report_path"],
            sample_files_folder=meta["folder"],
            nav_links=nav_links,
            key_vars=meta.get("key_vars"),
            hostname=meta["hostname"],
            report_session=shared_report_session,
        )

        site_reports.append(result)

    if progress_callback:
        progress_callback("Building homepage...")

    index_path = os.path.join(base_dir, "index.html")
    windowsReport.render_homepage(
        site_reports, output_path=index_path, report_session=shared_report_session
    )

    # return the generated homepage path and metadata for each report
    return index_path, site_reports


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Zip Audit - Report Builder")
        self.resizable(False, False)
        self.geometry("600x480")
        self.folders = []
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        tk.Label(
            self, text="Zip Audit Report Builder", font=("Arial", 14, "bold")
        ).pack(**pad, anchor="w")

        tk.Label(
            self,
            text=(
                f"Select up to {MAX_FOLDERS} host output folders.\n"
                "Each folder must contain the raw script output files directly inside it."
            ),
            justify="left",
            wraplength=560,
        ).pack(**pad, anchor="w")

        btn_frame = tk.Frame(self)
        btn_frame.pack(**pad, fill="x")

        tk.Button(
            btn_frame,
            text="Add Folder",
            command=self._add_folder,
            width=14,
            bg="#0066cc",
            fg="white",
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_frame, text="Remove Selected", command=self._remove_folder, width=16
        ).pack(side="left")

        tk.Label(self, text="Selected folders:").pack(**pad, anchor="w")

        list_frame = tk.Frame(self)
        list_frame.pack(padx=12, fill="both", expand=True)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.folder_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            height=8,
            selectmode=tk.SINGLE,
            font=("Courier New", 9),
        )
        self.folder_listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.folder_listbox.yview)

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(
            self,
            textvariable=self.status_var,
            fg="#444",
            font=("Arial", 9),
            wraplength=560,
            justify="left",
        ).pack(**pad, anchor="w")

        self.progress = ttk.Progressbar(self, mode="indeterminate", length=560)
        self.progress.pack(padx=12, pady=(0, 6), fill="x")

        tk.Button(
            self,
            text="Build Reports",
            command=self._build,
            bg="#198754",
            fg="white",
            font=("Arial", 11, "bold"),
            height=2,
        ).pack(padx=12, pady=8, fill="x")

    def _add_folder(self):
        if len(self.folders) >= MAX_FOLDERS:
            messagebox.showwarning(
                "Limit Reached", f"Maximum of {MAX_FOLDERS} folders allowed."
            )
            return

        path = filedialog.askdirectory(title="Select host output folder")
        if path and path not in self.folders:
            self.folders.append(path)
            self.folder_listbox.insert(tk.END, path)

    def _remove_folder(self):
        sel = self.folder_listbox.curselection()
        if sel:
            idx = sel[0]
            self.folder_listbox.delete(idx)
            self.folders.pop(idx)

    def _build(self):
        if not self.folders:
            messagebox.showwarning("No Folders", "Please add at least one folder.")
            return

        # start the progress indicator before the long-running build
        self.progress.start(10)
        self.status_var.set("Starting...")
        self.update()

        try:
            index_path, site_reports = run_pipeline(
                self.folders, progress_callback=self._update_status
            )

            self.progress.stop()
            names = ", ".join(s["hostname"] for s in site_reports)
            self.status_var.set(f"Done. Built: {names}")

            if messagebox.askyesno(
                "Complete",
                f"Reports built for {len(site_reports)} host(s).\n\nOpen the homepage now?",
            ):
                webbrowser.open(f"file:///{index_path.replace(os.sep, '/')}")

        except Exception as e:
            # stop the spinner and show the error state in the UI
            self.progress.stop()
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Build Failed", str(e))

    def _update_status(self, message):
        # update the status label with messages from run_pipeline
        self.status_var.set(message)
        self.update()


if __name__ == "__main__":
    app = App()
    app.mainloop()

# This rebuilds the .exe with PyInstaller, making sure to include all the necessary data files and hidden imports for the parsers and report modules.
# Adjust the paths as needed if your project structure differs.
"""
python -m PyInstaller --onefile --noconsole `
  --add-data "cheat_sheet.json;." `
  --add-data "linuxParser.py;." `
  --add-data "windowsParser.py;." `
  --add-data "linuxReport.py;." `
  --add-data "windowsReport.py;." `
  --hidden-import linuxParser `
  --hidden-import windowsParser `
  --hidden-import linuxReport `
  --hidden-import windowsReport `
  main.py
"""
