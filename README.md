# Script Report Builder

## Overview

Script Report Builder is a Python-based audit report engine that converts raw host collection output from Windows and Linux hosts into structured JSON and static HTML review artifacts.

The tool processes host evidence folders, converts raw script outputs into a normalized JSON contract, evaluates the parsed data against built-in control logic, and renders:
- per-host static HTML reports,
- a combined `index.html` homepage,
- supporting JSON artifacts in `output_json/`.

This project is intended for audit and control review workflows, not for active vulnerability scanning.

---

## Core Components

### `script-report-automatoin.py`
- Primary GUI entry point using Tkinter.
- Accepts up to 30 host folders.
- Detects host type and selects the correct parser and report generator.
- Writes output to `output_json/`, `reports/`, and `index.html`.
- Writes saved reports to `saved_reports/`.
- Opens the generated homepage if the user opts in.

### `windowsParser.py`
- Parses Windows evidence files into a normalized JSON payload.
- Exposes `build_windows_output(base_path, output_path)`.
- Reads files such as `01_systeminfo.txt`, `09_Services_Details.csv`, `14_RDPSettings_Master.txt`, `11_InstalledPatches.txt`, and more.

### `linuxParser.py`
- Parses Linux evidence files into a normalized JSON payload.
- Exposes `build_linux_output(base_path, output_path)`.
- Reads files such as `summary.csv`, `uname.txt`, `8.3_sshd_config.txt`, `sudoers.txt`, `shadow.txt`, and other CIS-style output files.

### `windowsReport.py`
- Evaluates Windows JSON data and renders HTML reports.
- Exposes `build_report(...)` and `render_homepage(...)`.
- Loads evidence files for display, applies OS-specific rule logic, and writes static HTML.

### `linuxReport.py`
- Evaluates Linux JSON data and renders HTML reports.
- Exposes `build_report(...)` and `render_homepage(...)`.
- Loads evidence files for display, applies OS-specific rule logic, and writes static HTML.

### `cheat_sheet.json`
- Support data file used by report logic.
- Provides auxiliary lookups such as insecure services and service classification.
- Easy extension point for new rule metadata without modifying core code.

---

## Execution Flow

### 1. Host Type Detection
`script-report-automation.py` determines OS type using marker files in each selected folder:
- Windows if `00_Analysis.txt` exists.
- Linux if `summary.csv` exists.
- otherwise the folder is skipped.

This is handled by `detect_os_type(folder)`.

### 2. Parsing
For each host folder, `script-report-automation.py` runs either:
- `build_windows_output(folder, temp_json_path)`
- `build_linux_output(folder, temp_json_path)`

Each parser reads a fixed list of expected evidence files and merges their parsed output into one JSON object.
Missing input files are generally handled gracefully by returning a placeholder rather than raising an exception.

### 3. JSON Output
The parser writes normalized JSON to a temporary file in `output_json/`, then renames it to a final output path based on hostname.

Output paths look like:
- `output_json/windows_output_{hostname}.json`
- `output_json/linux_output_{hostname}.json`

### 4. Report Building
`script-report-automation.py` then calls the report module for the host:
- `windowsReport.build_report(...)`
- `linuxReport.build_report(...)`

The report module loads the normalized JSON, loads evidence file content, evaluates each control, and writes a static HTML report.

### 5. Homepage Rendering
After all hosts are processed, the homepage is generated with `windowsReport.render_homepage(...)`.

The homepage aggregates:
- all requirement IDs,
- descriptions,
- host statuses,
- status counts,
- links to host reports.
- findings for each requirement per host, which can be viewed by expanding any requirement

---

## Report Output

### Generated artifacts
- `output_json/` - normalized host JSON files
- `reports/` - static per-host HTML reports
- `saved_reports/` - saved pages with a .json session key (which stores the current state of the analysis)
- `index.html` - combined homepage

### Per-host report contents
Each host report includes:
- requirement ID
- description
- current status
- evidence file list
- findings
- “look for” guidance
- QSA-style response text
- review modal for local edits

### Homepage contents
The homepage aggregates all hosts into a matrix view and supports export workflows.
It is the main comparison surface for multi-host analysis.

---

## Programming Model

### Parser contract
The parser modules act as the contract between raw evidence and report logic.
They produce dictionaries such as:
- `systeminfo`
- `sshd_config`
- `summary`
- `security_policies_local`
- `security_policies_domain`
- `running_services`
- `login_attempts`
- `pwquality`

Report modules assume these keys exist and use them to derive requirement results.

### Status values
Report rows use a fixed set of statuses (case-sensitive):
- `passed`
- `failed`
- `review`
- `manual`
- `unknown`

### Evidence preservation
The report renderer preserves raw evidence content for display.
Long files are truncated after 300 lines.

### Local persistence
Changes to reviews, as well as editor's notes, are saved in the page and are reflected when you load a saved report.

---

## Running Locally

### Prerequisites
- Python 3.9 or newer
- `tkinter` available for GUI mode
- The packages included in requirements.txt

### GUI mode
From the repository root:

```powershell
python script-report-automation.py
```

Then:
1. Select up to 30 host output folders.
2. Click `Build Reports`.
3. Choose whether to open `index.html` when prompted.

### Direct parser invocation
For JSON-only output, call parser builders directly:

```python
from linuxParser import build_linux_output
build_linux_output('sampleLinux1', 'output_json/linux_output_example.json')
```

---

## Packaging with PyInstaller

The project includes a PyInstaller command example in `script-report-automation.py`.

From the repo root:

```powershell
pyinstaller --onefile --noconsole `
  --add-data "cheat_sheet.json;." `
  --add-data "linuxParser.py;." `
  --add-data "windowsParser.py;." `
  --add-data "linuxReport.py;." `
  --add-data "windowsReport.py;." `
  --hidden-import linuxParser `
  --hidden-import windowsParser `
  --hidden-import linuxReport `
  --hidden-import windowsReport `
  script-report-automation.py
```

The resulting executable will include the parser and report modules plus the cheat sheet data.

---

## Development Notes

- Folder names do not matter for parsing; the pipeline relies on raw file names inside each folder.
- The pipeline currently limits GUI selection to 30 folders.
- `windowsReport.py` and `linuxReport.py` keep OS-specific control logic separate, with similar rendering patterns.
- `cheat_sheet.json` is the easiest extension point for additional rule metadata.

---

## Recommended Improvements

If you extend this codebase, consider:
- moving HTML generation into a templating layer in a separate program,
- adding unit tests for parser functions,
- making host detection configurable,
- separating rule definitions from renderer code.
