# main.py
# Main GUI and pipeline controller for the Script Output Report Builder.
# Detects host folders, determines whether they contain Linux or Windows output,
# normalizes the data via parsers, and generates JSON and HTML reports.

import os
import re
import sys
import json
import uuid
import webbrowser
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import simpledialog
import shutil

from linuxParser import build_linux_output
from windowsParser import build_windows_output
import linuxReport
from linuxReport import load_key_vars_linux
import windowsReport
from windowsReport import load_key_vars_windows

MAX_FOLDERS = 30
REQUIRED_MARKERS = {"windows": "00_Analysis.txt", "linux": "summary.csv"}

def get_base_dir():
    """Always write output next to the .exe or script, not in a temp folder."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# helper to avoid "'str' object has no attribute 'get'" when data is malformed
def as_dict(x):
    return x if isinstance(x, dict) else {}


# configure error logging to write `log.txt` next to the running exe/script
LOG_PATH = os.path.join(get_base_dir(), "log.txt")
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.ERROR,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


# this makes output land next to the script or the generated exe
def slugify(value):
    value = value.strip()
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value.strip("_") or "host"


def detect_os_type(folder):
    try:
        files_in_folder = os.listdir(folder)
    except OSError:
        return None

    # Exact filename markers must be present directly in the folder
    if REQUIRED_MARKERS["windows"] in files_in_folder:
        return "windows"
    if REQUIRED_MARKERS["linux"] in files_in_folder:
        return "linux"
    return None


def validate_folder(folder):
    """Validate a candidate host output folder.

    Returns (is_valid: bool, reason: str, os_type: str|None).
    """
    if not folder:
        return False, "No folder selected.", None
    if not os.path.isabs(folder):
        folder = os.path.abspath(folder)
    if not os.path.exists(folder):
        return False, "Path does not exist.", None
    if not os.path.isdir(folder):
        return False, "Path is not a directory.", None

    try:
        entries = os.listdir(folder)
    except OSError as e:
        return False, f"Unable to read folder: {e}", None

    # ensure marker files are directly in this folder (not nested)
    if REQUIRED_MARKERS["windows"] in entries:
        return True, "Contains Windows output files.", "windows"
    if REQUIRED_MARKERS["linux"] in entries:
        return True, "Contains Linux output files.", "linux"

    return (
        False,
        f"Required script output files not found directly in folder (looking for {REQUIRED_MARKERS}).",
        None,
    )


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

    # sanitize and enforce limits
    if not isinstance(sample_folders, (list, tuple)):
        raise TypeError("sample_folders must be a list of folder paths")

    # convert to absolute, preserve order, remove duplicates
    seen = set()
    sanitized = []
    for f in sample_folders:
        ab = os.path.abspath(f)
        if ab in seen:
            continue
        seen.add(ab)
        sanitized.append(ab)

    if len(sanitized) > MAX_FOLDERS:
        raise ValueError(f"At most {MAX_FOLDERS} folders are allowed")

    site_reports = []
    hosts_meta = []

    for i, folder in enumerate(sanitized):
        if progress_callback:
            progress_callback(f"Detecting OS for: {os.path.basename(folder)}...")

        valid, reason, os_type = validate_folder(folder)
        if not valid:
            if progress_callback:
                progress_callback(
                    f"WARNING: Skipping '{os.path.basename(folder)}' — {reason}"
                )
            continue

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
            try:
                data = build_windows_output(folder, temp_json_path)
            except Exception as e:
                if progress_callback:
                    progress_callback(f"ERROR parsing Windows folder {folder_name}: {e}")
                logging.exception("Error parsing Windows folder %s", folder_name)
                continue
            key_vars = load_key_vars_windows(data)
            hostname = as_dict(data.get("systeminfo")).get("Host Name") or "Unknown Host"
            slug = slugify(hostname)
            json_path = os.path.join(output_json, f"windows_output_{slug}.json")
            report_path = os.path.join(reports_dir, f"report_{slug}.html")
            report_module = windowsReport

        else:
            if progress_callback:
                progress_callback(f"Parsing Linux data: {folder_name}...")

            # parse the Linux evidence files and save a temp normalized JSON output
            try:
                data = build_linux_output(folder, temp_json_path)
            except Exception as e:
                if progress_callback:
                    progress_callback(f"ERROR parsing Linux folder {folder_name}: {e}")
                logging.exception("Error parsing Linux folder %s", folder_name)
                continue
            key_vars = load_key_vars_linux(data)
            hostname = (
                as_dict(data.get("summary")).get("Host")
                or as_dict(data.get("uname")).get("host")
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

    # return the generated homepage path, site report results, metadata from the hosts, and the report session
    # The report sessions
    return index_path, site_reports, hosts_meta, shared_report_session


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Script Output Report Builder")
        self.resizable(True, True)
        self.minsize(600, 500)
        self.geometry("600x540")
        self.folders = []
        self.last_build = None
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        tk.Label(
            self, text="Script Output Report Builder", font=("Arial", 14, "bold")
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
            selectmode=tk.EXTENDED,
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

        # Save report button and note
        save_frame = tk.Frame(self, relief="groove", bd=1)
        save_frame.pack(side="bottom", padx=12, pady=(0, 10), fill="x")

        self.save_button = tk.Button(
            save_frame,
            text="Save Current Report",
            command=self._save_report,
            width=18,
        )
        self.save_button.pack(side="left")
        self.save_button.config(state=tk.DISABLED)

        self.open_prev_button = tk.Button(
            save_frame,
            text="Open Previous Report",
            command=self._open_previous_report,
            width=18,
        )
        self.open_prev_button.pack(side="left", padx=(8, 0))

        # disable if no saved_reports directory exists
        saved_root = os.path.join(get_base_dir(), "saved_reports")
        if not os.path.isdir(saved_root) or not os.listdir(saved_root):
            self.open_prev_button.config(state=tk.DISABLED)

        tk.Label(
            save_frame,
            text="(Click to save; re-save after any manual edits)",
            fg="#666",
            font=("Arial", 9),
        ).pack(side="left", padx=(8, 0))

    def _add_folder(self):
        if len(self.folders) >= MAX_FOLDERS:
            messagebox.showwarning(
                "Limit Reached", f"Maximum of {MAX_FOLDERS} folders allowed."
            )
            return

        parent = filedialog.askdirectory(title="Select folder or parent folder to search")
        if not parent:
            return

        # If the selected folder itself contains the required files, add it directly.
        valid, reason, _ = validate_folder(parent)
        if valid:
            if parent not in self.folders:
                self.folders.append(parent)
                self.folder_listbox.insert(tk.END, parent)
            return

        # Recursively walk all subdirectories and collect every folder that
        # contains the required marker files, regardless of how deep they are.
        matches = []
        for dirpath, dirnames, filenames in os.walk(parent):
            # skip the root itself — already checked above
            if os.path.normpath(dirpath) == os.path.normpath(parent):
                continue
            v, _, _ = validate_folder(dirpath)
            if v:
                matches.append(dirpath)

        if not matches:
            messagebox.showerror(
                "No Valid Folders Found",
                f"No subfolders containing the required script output files were found "
                f"anywhere inside:\n\n{parent}",
            )
            return

        # Show a chooser with all discovered folders.
        chooser = tk.Toplevel(self)
        chooser.title("Select folders to add")
        chooser.geometry("600x400")

        tk.Label(
            chooser,
            text=f"Found {len(matches)} valid folder(s). Select the ones you want to add:",
        ).pack(anchor="w", padx=8, pady=(8, 0))

        listbox = tk.Listbox(chooser, selectmode=tk.EXTENDED, font=("Courier New", 9))
        scrollbar = tk.Scrollbar(chooser, orient=tk.VERTICAL, command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)
        listbox.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scrollbar.pack(side="left", fill="y", pady=8)

        for p in matches:
            # show the path relative to the parent so the list isn't cluttered
            label = os.path.relpath(p, parent)
            listbox.insert(tk.END, label)

        btn_frame = tk.Frame(chooser)
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))

        def on_add_selected():
            sel = listbox.curselection()
            for i in sel:
                if len(self.folders) >= MAX_FOLDERS:
                    messagebox.showwarning(
                        "Limit Reached",
                        f"Maximum of {MAX_FOLDERS} folders reached. Some folders were not added.",
                    )
                    break
                p = matches[i]
                if p not in self.folders:
                    self.folders.append(p)
                    self.folder_listbox.insert(tk.END, p)
            chooser.destroy()

        def on_cancel():
            chooser.destroy()

        tk.Button(
            btn_frame, text="Add Selected", command=on_add_selected,
            bg="#0066cc", fg="white", width=14,
        ).pack(side="left")
        tk.Button(
            btn_frame, text="Cancel", command=on_cancel, width=10,
        ).pack(side="left", padx=(8, 0))

        chooser.transient(self)
        chooser.grab_set()
        self.wait_window(chooser)

    def _remove_folder(self):
        # reverse order so popping by index doesn't shift remaining indices
        for idx in reversed(self.folder_listbox.curselection()):
            self.folder_listbox.delete(idx)
            self.folders.pop(idx)

    def _build(self):
        if not self.folders:
            messagebox.showwarning("No Folders", "Please add at least one folder.")
            return

        # If there's an unsaved previous build, ask whether to save it
        if self.last_build and not self.last_build.get("saved", False):
            if messagebox.askyesno(
                "Save previous report?",
                "You have a previous report that has not been saved.\n\nSave it now?",
            ):
                self._save_report()

        # validate all selected folders before starting
        invalid = []
        for f in self.folders:
            valid, reason, _ = validate_folder(f)
            if not valid:
                invalid.append((f, reason))

        if invalid:
            msg_lines = [f"{os.path.basename(p)}: {r}" for p, r in invalid]
            messagebox.showerror(
                "Invalid Folders",
                "The following selected folders are invalid or missing required files:\n\n"
                + "\n".join(msg_lines),
            )
            return

        # remind the user not to edit generated artifacts
        if not messagebox.askyesno(
            "Confirm",
            (
                "The tool will generate HTML and JSON files next to the application.\n\n"
                "Do not edit any generated files (index.html, the reports folder, the saved_reports folder, or the output_json folder).\n\n"
                "Continue?"
            ),
        ):
            return

        # warn that building will overwrite any existing unsaved generated files
        if not messagebox.askyesno(
            "Overwrite Warning",
            "This will overwrite any unsaved generated reports in the application folders. Continue?",
        ):
            return

        # start the progress indicator before the long-running build
        self.progress.start(10)
        self.status_var.set("Starting...")
        self.update()

        try:
            index_path, site_reports, hosts_meta, report_session = run_pipeline(
                self.folders, progress_callback=self._update_status
            )

            self.progress.stop()
            names = ", ".join(m["hostname"] for m in hosts_meta)
            self.status_var.set(f"Done. Built: {names}")

            if messagebox.askyesno(
                "Complete",
                f"Reports built for {len(hosts_meta)} host(s).\n\nOpen the homepage now?",
            ):
                webbrowser.open(f"file:///{index_path.replace(os.sep, '/')}")

            # store metadata about this build so the user can save it
            self.last_build = {
                "index_path": index_path,
                "site_reports": site_reports,
                "hosts_meta": hosts_meta,
                "report_session": report_session,
                "saved": False,
            }
            self.save_button.config(state=tk.NORMAL)

        except Exception as e:
            # stop the spinner and show the error state in the UI
            self.progress.stop()
            logging.exception("Build failed while running pipeline")
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Build Failed", str(e))

    def _update_status(self, message):
        # update the status label with messages from run_pipeline
        self.status_var.set(message)
        self.update()

    def _save_report(self):
        if not self.last_build:
            messagebox.showwarning("No Report", "There is no built report to save.")
            return

        name = simpledialog.askstring("Save Report", "Enter a name for this saved report:")
        if not name:
            return

        base_dir = get_base_dir()
        saved_root = os.path.join(base_dir, "saved_reports")
        os.makedirs(saved_root, exist_ok=True)

        folder_name = slugify(name)
        target_dir = os.path.join(saved_root, folder_name)

        if os.path.exists(target_dir):
            if not messagebox.askyesno(
                "Overwrite?",
                f"A saved report named '{folder_name}' already exists. Overwrite?",
            ):
                return
            shutil.rmtree(target_dir)

        os.makedirs(target_dir, exist_ok=True)

        #  collect current analysis state and write session_state.json 
        report_session = self.last_build.get("report_session", "")
        session_state = self._collect_session_state(report_session)
        state_path = os.path.join(target_dir, "session_state.json")
        try:
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(session_state, fh, indent=2)
        except Exception as e:
            logging.exception("Could not write session_state.json")
            messagebox.showerror("Save Failed", f"Could not write session state: {e}")
            return

        #  copy index.html 
        index_src = self.last_build.get("index_path")
        try:
            with open(index_src, "r", encoding="utf-8") as f:
                content = f.read()

            norm_base = os.path.normpath(base_dir)
            norm_base_unix = norm_base.replace("\\", "/")
            content = content.replace(norm_base + os.sep, "")
            content = content.replace(norm_base_unix + "/", "")
            content = content.replace(f"file:///{norm_base_unix}/", "")

            # inject bootstrap so localStorage is seeded when this saved copy opens
            content = self._inject_state_bootstrap(content, session_state)

            index_target = os.path.join(target_dir, "index.html")
            with open(index_target, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logging.exception("Failed saving index.html for saved report %s", target_dir)
            messagebox.showerror("Save Failed", f"Could not copy index.html: {e}")
            return

        #  copy per-host report and json files 
        reports_out = os.path.join(target_dir, "reports")
        output_json_out = os.path.join(target_dir, "output_json")
        os.makedirs(reports_out, exist_ok=True)
        os.makedirs(output_json_out, exist_ok=True)

        skipped = []
        for meta in self.last_build.get("hosts_meta", []):
            rpt = meta.get("report_path")
            jpath = meta.get("json_path")

            if rpt and os.path.exists(rpt):
                try:
                    # also inject the bootstrap into each individual report page
                    with open(rpt, "r", encoding="utf-8") as fh:
                        rpt_content = fh.read()
                    rpt_content = self._inject_state_bootstrap(rpt_content, session_state)
                    dest_rpt = os.path.join(reports_out, os.path.basename(rpt))
                    with open(dest_rpt, "w", encoding="utf-8") as fh:
                        fh.write(rpt_content)
                except Exception:
                    skipped.append(rpt)

            if jpath and os.path.exists(jpath):
                try:
                    shutil.copy2(jpath, os.path.join(output_json_out, os.path.basename(jpath)))
                except Exception:
                    skipped.append(jpath)

        self.last_build["saved"] = True
        self.save_button.config(state=tk.DISABLED)

        try:
            self.open_prev_button.config(state=tk.NORMAL)
        except Exception:
            pass

        if skipped:
            messagebox.showwarning(
                "Saved With Warnings",
                f"Saved to {target_dir}, but some files could not be copied:\n\n"
                + "\n".join(skipped),
            )
        else:
            messagebox.showinfo("Saved", f"Report saved to: {target_dir}")

    def _collect_session_state(self, report_session: str) -> dict:
        """Collect any sidecar *_state.json files written by the report pages."""
        state = {"report_session": report_session, "entries": {}}
        base_dir = get_base_dir()
        reports_dir = os.path.join(base_dir, "reports")
        if not os.path.isdir(reports_dir):
            return state
        for fn in os.listdir(reports_dir):
            if not fn.lower().endswith(".html"):
                continue
            stem = fn[:-5]
            sidecar = os.path.join(reports_dir, f"{stem}_state.json")
            if os.path.exists(sidecar):
                try:
                    with open(sidecar, "r", encoding="utf-8") as fh:
                        state["entries"][fn] = json.load(fh)
                except Exception:
                    logging.exception("Could not read state sidecar %s", sidecar)
        return state

    def _inject_state_bootstrap(self, html_content: str, session_state: dict) -> str:
        """Insert a <script> block that seeds localStorage from the saved state."""
        entries_js = json.dumps(session_state.get("entries", {}))
        session_js = json.dumps(session_state.get("report_session", ""))
        bootstrap = (
            f'<script id="__state_bootstrap__">\n'
            f'(function(){{\n'
            f'  var S={session_js}, E={entries_js};\n'
            f'  for(var k in E){{ try{{ localStorage.setItem(S+":"+k, JSON.stringify(E[k])); }}catch(e){{}} }}\n'
            f'  try{{ localStorage.setItem("report_session",S); }}catch(e){{}}\n'
            f'}})();\n'
            f'</script>'
        )
        # remove any previously injected block first
        html_content = re.sub(
            r'<script id="__state_bootstrap__">.*?</script>',
            "",
            html_content,
            flags=re.DOTALL,
        )
        # inject immediately after <head> so it runs before anything else
        for tag in ("<head>", "<HEAD>"):
            if tag in html_content:
                return html_content.replace(tag, f"{tag}\n{bootstrap}", 1)
        return bootstrap + "\n" + html_content

    def _open_previous_report(self):
        base_dir = get_base_dir()
        saved_root = os.path.join(base_dir, "saved_reports")
        if not os.path.isdir(saved_root):
            messagebox.showwarning("No Saved Reports", "No saved_reports folder exists.")
            return

        folder = filedialog.askdirectory(
            title="Select saved report folder", initialdir=saved_root
        )
        if not folder:
            return

        index_path = os.path.join(folder, "index.html")
        if not os.path.exists(index_path):
            messagebox.showerror(
                "Missing Index", "Selected folder does not contain index.html"
            )
            return

        # If the saved copy already has the bootstrap injected (from _save_report)
        # we are done — just open it.  The bootstrap will seed localStorage.
        webbrowser.open(f"file:///{index_path.replace(os.sep, '/')}")


if __name__ == "__main__":
    app = App()
    app.mainloop()

# Builder for Windows. Make sure to run in powershell
"""
python -m PyInstaller --clean --onefile --noupx --noconsole --log-level=INFO `
  --add-data 'cheat_sheet.json;.' `
  --add-data 'linuxParser.py;.' `
  --add-data 'windowsParser.py;.' `
  --add-data 'linuxReport.py;.' `
  --add-data 'windowsReport.py;.' `
  --hidden-import linuxParser `
  --hidden-import windowsParser `
  --hidden-import linuxReport `
  --hidden-import windowsReport `
  script-report-automation.py
"""

# Builder for Mac. This only works on Mac and Linux, not Windows. Make sure to run in bash or zsh
"""
python3 -m PyInstaller \
  --clean \
  --onefile \
  --windowed \
  --name "ScriptOutputReportBuilder" \
  --add-data "cheat_sheet.json:." \
  --add-data "linuxParser.py:." \
  --add-data "windowsParser.py:." \
  --add-data "linuxReport.py:." \
  --add-data "windowsReport.py:." \
  --hidden-import linuxParser \
  --hidden-import windowsParser \
  --hidden-import linuxReport \
  --hidden-import windowsReport \
  script-report-automation.py
  """
