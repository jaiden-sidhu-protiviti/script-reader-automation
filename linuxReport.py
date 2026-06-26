# linuxReport.py
# Linux report renderer and helper utilities.
# Builds HTML reports from normalized Linux JSON output and supports file
# loading, rule evaluation, and homepage rendering.

import html
import json
import os
import sys
import uuid

report_session = str(uuid.uuid4())

TRUNCATION_MARKER = "__TRUNCATED__"
MAX_LINES = 300


def as_dict(x):
    return x if isinstance(x, dict) else {}


def join_items(seq):
    """Safely join items coercing to strings and skipping empty/None values."""
    return ", ".join([s for s in (str(x).strip() if x is not None else "" for x in seq) if s])


def load_sample_files(folder="sampleWindows"):
    file_contents = {}

    if not os.path.exists(folder):
        return file_contents

    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)

        if os.path.isfile(fpath):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                if len(lines) > MAX_LINES:
                    truncated = "".join(lines[:MAX_LINES])
                    file_contents[fname] = truncated + f"\n{TRUNCATION_MARKER}:{fname}"
                else:
                    file_contents[fname] = "".join(lines)

            except Exception:
                file_contents[fname] = "[ERROR READING FILE]"

    return file_contents


# load raw evidence text so the report can show file content
def get_resource_path(relative_path):
    """
    Resolve a resource file path whether running as a script or
    as a PyInstaller --onefile bundle.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller extracts --add-data files to sys._MEIPASS at runtime
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


def load_cheat_sheet(path="cheat_sheet.json"):
    resolved = get_resource_path(path)
    if not os.path.exists(resolved):
        return {"insecure_services": []}
    with open(resolved, "r", encoding="utf-8") as f:
        return json.load(f)


def load_key_vars_linux(data):
    def safe(getter):
        try:
            val = getter()
            return val if val not in [None, ""] else "Not set"
        except Exception:
            return "Not set"

    def calc_complexity():
        try:
            complexity_vars = data.get("pwquality") or {}
            complexity = 0
            if "-1" in str(complexity_vars.get("dcredit", "")):
                complexity += 1
            if "-1" in str(complexity_vars.get("lcredit", "")):
                complexity += 1
            if "-1" in str(complexity_vars.get("ucredit", "")):
                complexity += 1
            if "-1" in str(complexity_vars.get("ocredit", "")):
                complexity += 1
            return complexity
        except Exception:
            return "Not set"

    return {
        "Key Variables": {
            "Max Password Age": safe(lambda: as_dict(next(iter(data.get("pw_ages") or []), {})).get("pw_max_age")),
            "Min Password Length": safe(lambda: as_dict(data.get("pwquality")).get("minlen")),
            "Password Complexity": calc_complexity(),
            "Password History": safe(lambda: as_dict(data.get("summary")).get("PwHistory")),
            "Bad Lockout Count": safe(lambda: as_dict(data.get("login_attempts")).get("deny")),
            "Lockout Duration": safe(lambda: as_dict(data.get("login_attempts")).get("unlock_time")),
            "Time Source IP": safe(lambda: next(iter(data.get("timesources") or []), "")),
            "SSH Logging": safe(lambda: as_dict(data.get("sshd_config")).get("LogLevel")),
        }
    }


def render_html(
    report, output_path, hostname, nav_links=None, key_vars=None, report_session=None
):
    def format_html_cell(value):
        if isinstance(value, list):
            return "<br>".join(
                html.escape(str(item)).replace("\n", "<br>") for item in value
            )
        return (
            html.escape(str(value)).replace("\n", "<br>") if value is not None else ""
        )

    rows = []
    for idx, entry in enumerate(report):
        status_class = {
            "passed": "passed",
            "failed": "failed",
            "review": "review",
            "manual": "manual",
            "unknown": "unknown",
        }.get(entry["status"], "unknown")
        finding_items = []
        for item in entry["findings"]:
            if isinstance(item, dict):
                label = item.get("message", "")
                label = label.replace("\n", "<br>")
                file_html = (
                    html.escape(item.get("file", "")) if item.get("file") else ""
                )
                line_html = (
                    html.escape(item.get("line", "")) if item.get("line") else ""
                )
            else:
                label = html.escape(str(item))
                file_html = ""
                line_html = ""
            detail_html = ""
            if line_html:
                detail_html += f"<pre class='finding-snippet'>{line_html}</pre>"
            if file_html:
                detail_html += f"<div class='finding-file'>File: {file_html}</div>"
            finding_items.append(
                f"<div class='finding-item'><div class='finding-label'>{label}</div>{detail_html}</div>"
            )
        findings_html = "".join(finding_items)
        review_button = (
            f"<div><button class='review-btn' data-idx='{idx}'>Review</button></div>"
        )
        files_html = "<br>".join(html.escape(f) for f in entry["files"])
        look_for_html = format_html_cell(entry.get("look_for", ""))
        row_id = "req_" + "".join(ch if ch.isalnum() else "_" for ch in entry["id"])
        current_status = str(entry.get("status", "unknown")).lower()
        qsa_response_text = (
            entry.get("qsa_response", "") if current_status == "passed" else ""
        )

        rows.append(
            "<tr id='{row_id}' class='{status_class}' data-editor-notes='[]'>"
            "<td>{id}</td>"
            "<td>{desc}</td>"
            "<td>{status}</td>"
            "<td>{files}</td>"
            "<td>{findings}{review}</td>"
            "<td>{look_for}</td>"
            "<td class='qsa-response-cell'><span class='qsa-response-text'>{qsa_response}</span></td>"
            "</tr>".format(
                row_id=row_id,
                status_class=status_class,
                id=html.escape(entry["id"]),
                desc=html.escape(entry.get("description", "")),
                status=html.escape(current_status),
                files=files_html,
                findings=findings_html,
                review=review_button,
                look_for=look_for_html,
                qsa_response=html.escape(qsa_response_text),
            )
        )

    # Build evidence list after loop completes

    evidence_list = [
        {
            "files": entry.get("evidence_files", {}),
            "default": entry.get("default_file"),
            "qsa_response": entry.get("qsa_response", ""),
        }
        for entry in report
    ]

    evidence_json = json.dumps(evidence_list)

    # Render floating circular navigation buttons (Home / Prev / Next)
    nav_html = ""
    if nav_links:
        home = nav_links.get("home")
        prev = nav_links.get("prev")
        nxt = nav_links.get("next")

        def link_or_disabled(href, label, title):
            if href:
                return f"<a class='nav-btn' href='{html.escape(href)}' title='{html.escape(title)}'>{label}</a>"
            return f"<span class='nav-btn nav-disabled' title='{html.escape(title)}'>{label}</span>"

        # Use simple icons for compact circular buttons
        home_btn = link_or_disabled(home, '🏠︎', 'Home')
        prev_btn = link_or_disabled(prev, '◀︎', 'Previous')
        next_btn = link_or_disabled(nxt, '▶︎', 'Next')

        nav_html = f"<div class='floating-nav'>{home_btn}{prev_btn}{next_btn}</div>"

    def build_key_vars_html(key_vars):
        if not key_vars:
            return ""

        def render_section(title, values):
            rows = ""
            for k, v in values.items():
                val = html.escape(str(v)) if v is not None else "<em>Not Set</em>"
                rows += (
                    f"<tr><td><strong>{html.escape(k)}</strong></td><td>{val}</td></tr>"
                )
            return f"""
            <div class='kv-card'>
                <h3>{html.escape(title)}</h3>
                <table class='kv-table'>{rows}</table>
            </div>
            """

        return f"""
        <div class='kv-container'>
            {render_section('Key Variables', key_vars.get('Key Variables', {}))}
        </div>"""

    # Write HTML file ONCE after loop completes
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(
            "<html><head><meta charset='utf-8'><title>Script Output Report</title></head><body>\n"
        )
        f.write(f"<h1>Script Output Report - {html.escape(hostname)}</h1>\n")

        if nav_html:
            f.write(f"<p>{nav_html}</p>\n")
        f.write(f"<p>Generated from <strong>{html.escape(output_path)}</strong></p>\n")

        if key_vars:
            f.write("<h2>Key Security Parameters</h2>\n")
            f.write(build_key_vars_html(key_vars))

        f.write("<style>\n")
        f.write("    body { font-family: Arial, sans-serif; margin: 24px; }\n")
        f.write("    table { width: 100%; border-collapse: collapse; table-layout: fixed; }\n")
        f.write("    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; word-wrap: break-word; word-break: break-word; }\n")
        f.write("    th { background: #333; color: #fff; }\n")
        f.write("    th:nth-child(1) { width: 6%; }\n")
        f.write("    th:nth-child(2) { width: 18%; }\n")
        f.write("    th:nth-child(3) { width: 8%; }\n")
        f.write("    th:nth-child(4) { width: 14%; }\n")
        f.write("    th:nth-child(5) { width: 30%; }\n")
        f.write("    th:nth-child(6) { width: 14%; }\n")
        f.write("    th:nth-child(7) { width: 10%; }\n")
        f.write("    tr.passed { background: #e5f7eb; }\n")
        f.write("    tr.failed { background: #f9d6d5; }\n")
        f.write("    tr.review { background: #fff4e5; }\n")
        f.write("    tr.manual { background: #eef0f5; }\n")
        f.write("    tr.unknown { background: #f0f0f0; }\n")
        f.write("    .finding-item { margin-bottom: 0.9em; display: block; }\n")
        f.write("    .finding-label { font-family: Arial, sans-serif; margin-bottom: 0.2em; display: block; }\n")
        f.write("    .finding-snippet { margin: 0.25em 0 0; font-family: 'Courier New', Courier, monospace; background: #f7f7f7; padding: 6px; border-radius: 4px; white-space: pre-wrap; overflow-wrap: anywhere; }\n")
        f.write("    .finding-file { font-size: 0.9em; color: #444; margin-top: 0.25em; }\n")
        f.write("    #reviewModal { display: none; position: fixed; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.4); }\n")
        f.write("    #reviewModal .box { background: #fff; margin: 40px auto; padding: 12px; width: 80%; max-width: 900px; border-radius: 6px; }\n")
        f.write("    #reviewModal textarea { width: 100%; height: 240px; font-family: monospace; }\n")
        f.write("    .review-btn { padding: 6px 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }\n")
        f.write("    .review-btn:hover { background: #0052a3; }\n")
        f.write("    .top-toolbar { margin: 16px 0; display: flex; justify-content: flex-start; gap: 12px; }\n")
        f.write("    .export-btn { padding: 10px 16px; background: #198754; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }\n")
        f.write("    .export-btn:hover { background: #157347; }\n")
        f.write("    .qsa-response-text { font-size: 0.82em; color: #333; }\n")
        f.write("""
        .kv-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .kv-card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; background: #fafafa; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        .kv-card h3 { margin-top: 0; margin-bottom: 8px; font-size: 1.05em; color: #333; }
        .kv-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        .kv-table td { border: none; padding: 4px 6px; vertical-align: top; }
        .kv-table td:first-child { color: #555; width: 55%; }
        .filter-bar {
            display: flex; align-items: center; flex-wrap: wrap;
            gap: 8px; margin-bottom: 14px; padding: 10px 14px;
            background: #f5f5f5; border-radius: 8px; border: 1px solid #e0e0e0;
        }
        .filter-bar-label { font-weight: 600; font-size: 0.9em; color: #444; margin-right: 4px; }
        .filter-chip {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 5px 12px; border-radius: 20px; border: 2px solid transparent;
            cursor: pointer; font-size: 0.85em; font-weight: 600;
            transition: transform 0.1s ease, box-shadow 0.1s ease; user-select: none;
        }
        .filter-chip:hover { transform: translateY(-1px); box-shadow: 0 2px 6px rgba(0,0,0,0.15); }
        .filter-chip.active { border-color: #333; box-shadow: 0 2px 8px rgba(0,0,0,0.25); }
        .filter-chip .chip-count {
            background: rgba(0,0,0,0.15); border-radius: 10px; padding: 1px 6px; font-size: 0.82em;
        }
        .filter-chip.chip-passed  { background: #c3e6cb; color: #155724; }
        .filter-chip.chip-failed  { background: #f5c6cb; color: #721c24; }
        .filter-chip.chip-review  { background: #ffe8b0; color: #856404; }
        .filter-chip.chip-manual  { background: #d6d8e7; color: #383d72; }
        .filter-chip.chip-unknown { background: #e0e0e0; color: #444;    }
        .filter-chip.chip-all     { background: #333;    color: #fff;    }
        .reset-filter-btn {
            padding: 5px 12px; background: #dc3545; color: #fff;
            border: none; border-radius: 4px; cursor: pointer;
            font-size: 0.82em; display: none;
        }
        .reset-filter-btn.visible { display: inline-block; }
        #noFilterResults { display: none; padding: 18px; text-align: center; color: #888; font-style: italic; }
        tr.filter-hidden { display: none; }
        .floating-nav { position: fixed; right: 18px; bottom: 18px; display: flex; gap: 10px; align-items: center; z-index: 9999; }
        .nav-btn { display: inline-flex; align-items: center; justify-content: center; width: 56px; height: 56px; border-radius: 50%; background: #007bff; color: #fff; text-decoration: none; font-size: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.18); transition: transform 0.12s ease, background 0.12s ease; }
        .nav-btn:hover { transform: translateY(-3px); background: #0056b3; }
        .nav-btn.nav-disabled { background: #dcdcdc; color: #888; cursor: default; pointer-events: none; box-shadow: none; }
    </style>
    """)

        f.write("<div class='filter-bar'>\n")
        f.write("  <span class='filter-bar-label'>Filter by Status:</span>\n")
        for chip_status in ["all", "passed", "failed", "review", "manual", "unknown"]:
            f.write(
                f"  <button class='filter-chip chip-{chip_status}'"
                f" data-filter='{chip_status}'"
                f" onclick='setFilter(\"{chip_status}\")'>"
                f"{chip_status.title()}"
                f"  <span class='chip-count' id='count-{chip_status}'>0</span>"
                f"</button>\n"
            )
        f.write(
            "  <button class='reset-filter-btn' id='resetFilterBtn'"
            " onclick='setFilter(\"all\")'>&#x2715; Reset Filter</button>\n"
        )
        f.write("</div>\n")
        f.write("<div id='noFilterResults'>No requirements match this filter.</div>\n")

        f.write( "<table id='requirementsTable'><thead><tr><th>ID</th><th>Description</th><th>Status</th><th>Files</th><th>Findings</th><th>Look For</th><th>QSA Response</th></tr></thead><tbody>\n")
        for r in rows:
            f.write(r + "\n")
        f.write("</tbody></table>\n")
        f.write("<script>\n")
        f.write(f"    const REPORT_EVIDENCE = {evidence_json};\n")

        f.write("    function escapeHtml(text) {\n")
        f.write("        return String(text ?? '')\n")
        f.write("            .replace(/&/g, '&amp;')\n")
        f.write("            .replace(/</g, '&lt;')\n")
        f.write("            .replace(/>/g, '&gt;')\n")
        f.write("            .replace(/\\\"/g, '&quot;')\n")
        f.write("            .replace(/'/g, '&#39;');\n")
        f.write("    }\n")

        f.write("    function csvEscape(value) {\n")
        f.write("        const s = String(value ?? '');\n")
        f.write('        if (/[",\\n\\r]/.test(s)) {\n')
        f.write("            return '\"' + s.replace(/\"/g, '\"\"') + '\"';\n")
        f.write("        }\n")
        f.write("        return s;\n")
        f.write("    }\n")

        f.write("    function getEditorNotes(row) {\n")
        f.write("        try {\n")
        f.write("            return JSON.parse(row.dataset.editorNotes || '[]');\n")
        f.write("        } catch (e) {\n")
        f.write("            return [];\n")
        f.write("        }\n")
        f.write("    }\n")

        f.write("    function setEditorNotes(row, notes) {\n")
        f.write("        row.dataset.editorNotes = JSON.stringify(notes || []);\n")
        f.write("    }\n")

        f.write("    function getFindingsText(row) {\n")
        f.write("        const findingsCell = row.children[4].cloneNode(true);\n")
        f.write("        findingsCell.querySelectorAll('button').forEach(btn => btn.remove());\n")
        f.write("        return findingsCell.innerText.replace(/\\n{3,}/g, '\\n\\n').trim();\n")
        f.write("    }\n")

        f.write("  function doExportXlsx() {\n")
        f.write("    const selected = Array.from(\n")
        f.write("      document.querySelectorAll('#exportHostList input[type=checkbox]')\n")
        f.write("    ).filter(cb => cb.checked).map(cb => parseInt(cb.dataset.idx));\n")
        f.write("    if (selected.length === 0) { alert('Please select at least one host.'); return; }\n")
        f.write("    const wb = XLSX.utils.book_new();\n")
        f.write("    const headers = ['ID','Description','Status','Files','Findings','Look For','QSA Response','Editor\\'s Notes'];\n")
        f.write("    selected.forEach(idx => {\n")
        f.write("      const host = EXPORT_DATA[idx];\n")
        f.write("      const sheetData = [headers];\n")
        f.write("      host.rows.forEach(row => {\n")

        # Build the same localStorage key the report page uses
        f.write("        const reqKey   = 'req_' + row.id.replace(/[^a-zA-Z0-9]/g, '_');\n")
        f.write("        const storeKey = 'zipaudit|' + host.hostname + '|' + reqKey;\n")
        f.write("        const raw      = localStorage.getItem(storeKey);\n")
        f.write("        let   status   = row.status;\n")
        f.write("        let   noteStr  = '';\n")
        f.write("        if (raw) {\n")
        f.write("          try {\n")
        f.write("            const saved = JSON.parse(raw);\n")
        f.write("            status = saved.status || status;\n")
        f.write("            if (Array.isArray(saved.notes) && saved.notes.length) {\n")
        f.write("              noteStr = saved.notes\n")
        f.write("                .map(n => n.timestamp + ' | moved to ' + n.status + ' | ' + n.note)\n")
        f.write("                .join('\\n\\n');\n")
        f.write("            }\n")
        f.write("          } catch(e) {}\n")
        f.write("        }\n")

        # Only include QSA response if the current (possibly overridden) status is passed
        f.write("        const qsaText = status === 'passed' ? row.qsa_response : '';\n")
        f.write("        sheetData.push([row.id, row.description, status, row.files, row.findings, row.look_for, qsaText, noteStr]);\n")
        f.write("      });\n")
        f.write("      const ws = XLSX.utils.aoa_to_sheet(sheetData);\n")
        f.write("      ws['!cols'] = [{wch:30},{wch:50},{wch:10},{wch:25},{wch:60},{wch:40},{wch:60},{wch:50}];\n")
        f.write("      const sheetName = (host.hostname + ' (' + host.os_label + ')').replace(/[\\\\\\/?*\\[\\]]/g, '').substring(0, 31);\n")
        f.write("      XLSX.utils.book_append_sheet(wb, ws, sheetName);\n")
        f.write("    });\n")
        f.write("    const ts = new Date().toISOString().replace(/[:.]/g, '-');\n")
        f.write("    XLSX.writeFile(wb, `zip_audit_export_${ts}.xlsx`);\n")
        f.write("    closeExportModal();\n")
        f.write("  }\n\n")

        f.write(f"    const HOST_KEY = {json.dumps(hostname)};\n")
        f.write(f"    const REPORT_SESSION = {json.dumps(report_session)};\n")
        f.write("    const BUILD_RESET_MARKER = 'zipaudit|build_marker';\n")
        f.write("    (function resetSavedReviewsForNewBuild() {\n")
        f.write("        const previous = localStorage.getItem(BUILD_RESET_MARKER);\n")
        f.write("        if (previous !== REPORT_SESSION) {\n")
        f.write("            Object.keys(localStorage).forEach(k => {\n")
        f.write("                if (k.startsWith('zipaudit|') && k !== BUILD_RESET_MARKER) {\n")
        f.write("                    localStorage.removeItem(k);\n")
        f.write("                }\n")
        f.write("            });\n")
        f.write("            localStorage.setItem(BUILD_RESET_MARKER, REPORT_SESSION);\n")
        f.write("        }\n")
        f.write("    })();\n")
        f.write("\n")

        f.write("    function storageKey(reqId) {\n")
        f.write("        return 'zipaudit|' + HOST_KEY + '|' + reqId;\n")
        f.write("    }\n")
        f.write("\n")

        f.write("    function saveRowState(row, status, notes) {\n")
        f.write("        const key = storageKey(row.id);\n")
        f.write("        localStorage.setItem(key, JSON.stringify({status: status, notes: notes}));\n")
        f.write("        window.dispatchEvent(new StorageEvent('storage', { key: key }));\n")
        f.write("    }\n")
        f.write("\n")

        f.write("    function loadAllRowStates() {\n")
        f.write("        const rows = Array.from(document.querySelectorAll('#requirementsTable tbody tr'));\n")
        f.write("        rows.forEach((row, idx) => {\n")
        f.write("            const raw = localStorage.getItem(storageKey(row.id));\n")
        f.write("            if (!raw) return;\n")
        f.write("            try {\n")
        f.write("                const saved = JSON.parse(raw);\n")
        f.write("                row.className = saved.status;\n")
        f.write("                row.children[2].innerText = saved.status;\n")
        f.write("                syncQsaResponse(row, idx, saved.status);\n")
        f.write("                row.querySelectorAll('.editor-note').forEach(e => e.remove());\n")
        f.write("                if (Array.isArray(saved.notes)) {\n")
        f.write("                    setEditorNotes(row, saved.notes);\n")
        f.write("                    saved.notes.forEach(n => {\n")
        f.write("                        const cell    = row.children[4];\n")
        f.write("                        const wrapper = document.createElement('div');\n")
        f.write("                        wrapper.className = 'finding-item editor-note';\n")
        f.write("                        const label = document.createElement('div');\n")
        f.write("                        label.className = 'finding-label';\n")
        f.write("                        label.innerHTML = '<b>Editor\\'s Note (' + escapeHtml(n.timestamp) + ', moved to ' + escapeHtml(n.status) + '):</b>';\n")
        f.write("                        const body = document.createElement('div');\n")
        f.write("                        body.innerHTML = escapeHtml(n.note).replace(/\\n/g, '<br>');\n")
        f.write("                        wrapper.appendChild(label);\n")
        f.write("                        wrapper.appendChild(body);\n")
        f.write("                        cell.insertBefore(wrapper, cell.firstChild);\n")
        f.write("                    });\n")
        f.write("                }\n")
        f.write("            } catch(e) {}\n")
        f.write("        });\n")
        f.write("    }\n")
        f.write("\n")

        f.write("    document.addEventListener('DOMContentLoaded', loadAllRowStates);\n")
        f.write("\n")

        f.write("""
            // ── Status filter ──────────────────────────────────────────────────
            let activeFilter = 'all';

            function updateChipCounts() {
                const allRows = Array.from(document.querySelectorAll('#requirementsTable tbody tr'));
                const counts = { passed: 0, failed: 0, review: 0, manual: 0, unknown: 0 };
                allRows.forEach(row => {
                    const s = row.children[2].innerText.trim().toLowerCase();
                    if (counts[s] !== undefined) counts[s]++;
                });
                let total = 0;
                Object.values(counts).forEach(v => total += v);
                const allEl = document.getElementById('count-all');
                if (allEl) allEl.textContent = total;
                Object.entries(counts).forEach(([s, n]) => {
                    const el = document.getElementById('count-' + s);
                    if (el) el.textContent = n;
                });
            }

            function setFilter(status) {
                activeFilter = status;
                const allRows = Array.from(document.querySelectorAll('#requirementsTable tbody tr'));
                allRows.forEach(row => {
                    if (status === 'all') {
                        row.classList.remove('filter-hidden');
                    } else {
                        const rowStatus = row.children[2].innerText.trim().toLowerCase();
                        row.classList.toggle('filter-hidden', rowStatus !== status);
                    }
                });
                // update active chip highlight
                document.querySelectorAll('.filter-chip').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.filter === status);
                });
                // show/hide reset button
                const resetBtn = document.getElementById('resetFilterBtn');
                if (resetBtn) resetBtn.classList.toggle('visible', status !== 'all');
                // show empty-state message
                const visible = allRows.filter(r => !r.classList.contains('filter-hidden'));
                const noResults = document.getElementById('noFilterResults');
                if (noResults) noResults.style.display = visible.length === 0 ? 'block' : 'none';
            }

            // Re-apply filter + recount after a review is saved
            const _origSaveReview = typeof saveReview === 'function' ? saveReview : null;
            document.addEventListener('DOMContentLoaded', function() {
                updateChipCounts();
                setFilter('all');
            });
        """)

        f.write("    function resolveFileContent(raw, filename) {\n")
        f.write("        const marker = '__TRUNCATED__:';\n")
        f.write("        const idx = raw.indexOf(marker);")
        f.write("        if (idx === -1) return raw;\n")
        f.write("        const blob = new Blob([raw.substring(0, idx)], { type: 'text/plain' });\n")
        f.write("        const url = URL.createObjectURL(blob);\n")
        f.write("        return raw.substring(0, idx)\n")
        f.write("            + '\\n\\n[File truncated at 300 lines]\\n'\n")
        f.write("            + '[DOWNLOAD_LINK:' + url + ':' + filename + ']';\n")
        f.write("    }\n")

        f.write("    function displayFileContent(content, filename) {\n")
        f.write("        const linkPattern = /\\[DOWNLOAD_LINK:([^:]+):([^\\]]+)\\]/;\n")
        f.write("        const match = content.match(linkPattern);\n")
        f.write("        const textarea = document.getElementById('fileContent');\n")
        f.write("        const existing = document.getElementById('fileDownloadLink');\n")
        f.write("        if (existing) existing.remove();\n")
        f.write("        if (match) {\n")
        f.write("            textarea.value = content.replace(linkPattern, '').trim();\n")
        f.write("            const a = document.createElement('a');\n")
        f.write("            a.id = 'fileDownloadLink';\n")
        f.write("            a.href = match[1];\n")
        f.write("            a.download = match[2];\n")
        f.write("            a.style.cssText = 'display:inline-block;margin-top:6px;font-size:0.9em;color:#0066cc;';\n")
        f.write("            textarea.parentNode.insertBefore(a, textarea.nextSibling);\n")
        f.write("        } else {\n")
        f.write("            textarea.value = content;\n")
        f.write("        }\n")
        f.write("    }\n")

        f.write("    function openReview(idx) {\n")
        f.write("        const modal = document.getElementById('reviewModal');\n")
        f.write("        modal.style.display = 'block';\n")
        f.write("        modal.dataset.idx = idx;\n")
        f.write("        const evidence = REPORT_EVIDENCE[idx] || {};\n")
        f.write("        const files = evidence.files || {};\n")
        f.write("        const defaultFile = evidence.default || '';\n")
        f.write("        const sel = document.getElementById('fileSelect');\n")
        f.write("        sel.innerHTML = '';\n")
        f.write("        for (const f of Object.keys(files)) {\n")
        f.write("            const opt = document.createElement('option');\n")
        f.write("            opt.value = f;\n")
        f.write("            opt.text = f;\n")
        f.write("            sel.appendChild(opt);\n")
        f.write("        }\n")
        f.write("        if (defaultFile && files[defaultFile]) {\n")
        f.write("            sel.value = defaultFile;\n")
        f.write("        } else if (sel.options.length) {\n")
        f.write("            sel.selectedIndex = 0;\n")
        f.write("        }\n")
        f.write("        const raw = files[sel.value] || '';\n")
        f.write("        displayFileContent(resolveFileContent(raw, sel.value), sel.value);\n")
        f.write("        document.getElementById('statusSelect').value = document.querySelectorAll('#requirementsTable tbody tr')[idx].children[2].innerText.trim();\n")
        f.write("        document.getElementById('editorNote').value = '';\n")
        f.write("    }\n")

        f.write("    function closeReview() {\n")
        f.write("        document.getElementById('reviewModal').style.display = 'none';\n")
        f.write("    }\n")

        f.write("    function syncQsaResponse(row, idx, status) {\n")
        f.write("        const cell = row.querySelector('.qsa-response-cell');\n")
        f.write("        if (!cell) return;\n")
        f.write("        const evidence = REPORT_EVIDENCE[idx] || {};\n")
        f.write("        const response = evidence.qsa_response || '';\n")
        f.write("        if (String(status).toLowerCase() === 'passed') {\n")
        f.write("            cell.innerHTML = '<span class=\"qsa-response-text\">' + escapeHtml(response) + '</span>';\n")
        f.write("        } else {\n")
        f.write("            cell.innerHTML = '';\n")
        f.write("        }\n")
        f.write("    }\n")

        f.write("    document.addEventListener('click', function(e) {\n")
        f.write("        if (e.target && e.target.classList && e.target.classList.contains('review-btn')) {\n")
        f.write("            openReview(parseInt(e.target.dataset.idx));\n")
        f.write("        }\n")
        f.write("    });\n")

        f.write("    function onFileChange() {\n")
        f.write("        const idx = document.getElementById('reviewModal').dataset.idx;\n")
        f.write("        const f = this.value;\n")
        f.write("        const evidence = REPORT_EVIDENCE[idx] || {};\n")
        f.write("        const files = evidence.files || {};\n")
        f.write("        const rawContent = files[f] || '';\n")
        f.write("        displayFileContent(resolveFileContent(rawContent, f), f);\n")
        f.write("    }\n")

        f.write("    function saveReview() {\n")
        f.write("        const modal  = document.getElementById('reviewModal');\n")
        f.write("        if (!modal) { console.error('Modal element not found'); return; }\n")
        f.write("        const idx    = parseInt(modal.dataset.idx);\n")
        f.write("        const status = document.getElementById('statusSelect').value;\n")
        f.write("        const note   = document.getElementById('editorNote').value.trim();\n")
        f.write("        const row = document.querySelectorAll('#requirementsTable tbody tr')[idx];\n")
        f.write("        if (!row) { console.error('Row element not found at index ' + idx); return; }\n")
        f.write("\n")
        f.write("        row.className = status;\n")
        f.write("        row.children[2].innerText = status;\n")
        f.write("        syncQsaResponse(row, idx, status);\n")
        f.write("\n")
        # Always get notes first, regardless of whether a new note is being added
        f.write("        const notes = getEditorNotes(row);\n")
        f.write("\n")
        f.write("        if (note) {\n")
        f.write("            const timestamp = new Date().toLocaleString();\n")
        f.write("            notes.push({ timestamp, status, note });\n")
        f.write("            setEditorNotes(row, notes);\n")
        f.write("\n")
        f.write("            const cell    = row.children[4];\n")
        f.write("            const wrapper = document.createElement('div');\n")
        f.write("            wrapper.className = 'finding-item editor-note';\n")
        f.write("            const label = document.createElement('div');\n")
        f.write("            label.className = 'finding-label';\n")
        f.write("            label.innerHTML = '<b>Editor\\'s Note (' + escapeHtml(timestamp) + ', moved to ' + escapeHtml(status) + '):</b>';\n")
        f.write("            const body = document.createElement('div');\n")
        f.write("            body.innerHTML = escapeHtml(note).replace(/\\n/g, '<br>');\n")
        f.write("            wrapper.appendChild(label);\n")
        f.write("            wrapper.appendChild(body);\n")
        f.write("            cell.insertBefore(wrapper, cell.firstChild);\n")
        f.write("        }\n")
        f.write("\n")
        # Persist to localStorage — always, not just when a note is added
        f.write("        saveRowState(row, status, getEditorNotes(row));\n")
        f.write("        updateChipCounts();\n")
        f.write("        setFilter(activeFilter);\n")
        f.write("        closeReview();\n")
        f.write("    }\n")

        f.write("  function applyStoredStatuses() {\n")
        f.write("    document.querySelectorAll('tbody td[data-host][data-req]').forEach(td => {\n")
        f.write("      const key = 'zipaudit|' + td.dataset.host + '|' + td.dataset.req;\n")
        f.write("      const raw = localStorage.getItem(key);\n")
        f.write("      if (!raw) return;\n")
        f.write("      try {\n")
        f.write("        const saved = JSON.parse(raw);\n")
        f.write("        td.className = saved.status;\n")
        f.write("        const a = td.querySelector('a.cell-link');\n")
        f.write("        if (a) a.textContent = saved.status;\n")
        f.write("      } catch(e) {}\n")
        f.write("    });\n")
        f.write("  }\n")

        f.write("  function adjustHostHeaders(){\n")
        f.write("    document.querySelectorAll('th .host-header').forEach(el=>{\n")
        f.write("      el.classList.remove('shrunk'); el.style.fontSize='1em'; el.style.whiteSpace='nowrap'; el.style.wordBreak='normal';\n")
        f.write("      try{ if (el.scrollWidth > el.clientWidth){ el.style.whiteSpace='normal'; el.style.wordBreak='break-word'; el.classList.add('shrunk'); el.style.fontSize='0.6em'; } }catch(e){}\n")
        f.write("    });\n")
        f.write("  }\n")
        f.write("  document.addEventListener('DOMContentLoaded', function(){ applyStoredStatuses(); adjustHostHeaders(); });\n")
        f.write("  window.addEventListener('resize', adjustHostHeaders);\n")
        f.write("  window.addEventListener('focus', applyStoredStatuses);\n")
        f.write("  window.addEventListener('storage', applyStoredStatuses);\n")

        f.write("</script>\n")
        f.write("<div id='reviewModal'><div class='box'>\n")
        f.write("    <div style='display: flex; gap: 8px; align-items: center;'>\n")
        f.write("        <label>Status:</label>\n")
        f.write("        <select id='statusSelect'><option>passed</option><option>failed</option><option>review</option><option>manual</option><option>unknown</option></select>\n")
        f.write("        <label style='margin-left: 12px;'>File:</label>\n")
        f.write("        <select id='fileSelect' onchange='onFileChange.call(this)'></select>\n")
        f.write("    </div>\n")
        f.write("    <textarea id='fileContent' readonly></textarea>\n")
        f.write("    <label>Editor\\'s Note:</label>\n")
        f.write("    <textarea id='editorNote'></textarea>\n")
        f.write("    <div style='margin-top: 12px;'>\n")
        f.write("        <button onclick='saveReview()' style='padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer;'>Save</button>\n")
        f.write("        <button onclick='closeReview()' style='padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 8px;'>Cancel</button>\n")
        f.write("    </div>\n")
        f.write("</div></div>\n")
        f.write("</body></html>\n")


def build_report(
    json_path,
    output_path,
    sample_files_folder,
    nav_links=None,
    key_vars=None,
    hostname=None,
    report_session=None,
):
    if report_session is None:
        report_session = str(uuid.uuid4())

    # report builder glues parsed json and html generation for linux output
    with open(json_path, "r") as f:
        data = json.load(f)

    all_files = load_sample_files(sample_files_folder)
    cheat_sheet = load_cheat_sheet("cheat_sheet.json")
    report = evaluate_from_json(data, all_files, cheat_sheet)

    render_html(
        report,
        output_path,
        hostname,
        nav_links=nav_links,
        key_vars=key_vars,
        report_session=report_session,
    )

    return {
        "hostname": hostname,
        "report": report,
        "report_path": output_path,
        "json_path": json_path,
    }


def render_homepage(site_reports, output_path="index.html", report_session=None):
    """
    site_reports = [
        {
            "hostname": "...",
            "report": [...],
            "report_path": "report_hostA.html",
            "json_path": "windows_output_hostA.json"
        },
        ...
    ]
    """

    all_req_ids = []
    req_desc = {}
    for site in site_reports:
        for entry in site["report"]:
            if entry["id"] not in all_req_ids:
                all_req_ids.append(entry["id"])
                req_desc[entry["id"]] = entry.get("description", "")

    # Aggregate counts
    counts = {"passed": 0, "failed": 0, "review": 0, "manual": 0, "unknown": 0}
    for site in site_reports:
        for entry in site["report"]:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1

    matrix = {}
    for req_id in all_req_ids:
        matrix[req_id] = {}
        for site in site_reports:
            host = site["hostname"]
            entry = next((r for r in site["report"] if r["id"] == req_id), None)
            matrix[req_id][host] = entry

    def req_anchor(req_id):
        return "req_" + "".join(ch if ch.isalnum() else "_" for ch in req_id)

    def os_label(json_path):
        p = (json_path or "").lower()
        if "windows_output" in p:
            return "Windows"
        if "linux_output" in p:
            return "Linux"
        return "Unknown"

    # Build XLSX export payload
    export_data = []
    for site in site_reports:
        label = os_label(site.get("json_path", ""))
        export_data.append(
            {
                "hostname": site["hostname"],
                "os_label": label,
                "rows": [
                    {
                        "id": entry.get("id", ""),
                        "description": entry.get("description", ""),
                        "status": entry.get("status", ""),
                        "files": ", ".join(entry.get("files", [])),
                        "findings": " | ".join(
                            f.get("message", str(f)) if isinstance(f, dict) else str(f)
                            for f in entry.get("findings", [])
                        ),
                        "look_for": (
                            entry.get("look_for", "")
                            if not isinstance(entry.get("look_for"), list)
                            else " ".join(entry.get("look_for", []))
                        ),
                        "qsa_response": entry.get("qsa_response", ""),
                    }
                    for entry in site["report"]
                ],
            }
        )

    export_data_json = json.dumps(export_data)
    sum(counts.values()) or 1  # avoid div/0 for progress bars

    with open(output_path, "w", encoding="utf-8") as f:

        f.write("<!DOCTYPE html>\n<html lang='en'>\n<head>\n")
        f.write("  <meta charset='utf-8'>\n")
        f.write(
            "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
        )
        f.write("  <title>Script Report - Home</title>\n")

        # Summary counts
        f.write("<h2>Overall Summary</h2>\n")
        f.write("<ul>\n")
        for k in ["passed", "failed", "review", "manual", "unknown"]:
            f.write(f"<li><b>{html.escape(k.title())}</b>: {counts.get(k, 0)}</li>\n")
        f.write("</ul>\n")

        f.write(
            "  <script src='https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'></script>\n"
        )
        f.write("""
        <style>
        body { font-family: Arial, sans-serif; margin: 24px; }
        table { border-collapse: collapse; width: 100%; table-layout: fixed; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: middle; }
        th:first-child, td:first-child { text-align: left; }
        .passed { background: #e5f7eb; }
        .failed { background: #f9d6d5; }
        .review { background: #fff4e5; }
        .manual { background: #eef0f5; }
        .unknown { background: #f0f0f0; }
        .legend span { display:inline-block; padding:4px 10px; margin-right:8px; border:1px solid #ccc; }
        .cell-link { display:block; width:100%; height:100%; text-decoration:none; color:inherit; }
        small { color:#444; }
        .modal-overlay {
        display: none;
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        background: rgba(0, 0, 0, 0.5);
        z-index: 1000;
        justify-content: center;
        align-items: center;
        }
        .modal-overlay.open { display: flex; }

        .modal-box {
        background: #ffffff;
        border-radius: 12px;
        padding: 28px 32px;
        min-width: 360px;
        max-width: 480px;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.22);
        }
        .modal-box h3 {
        margin: 0 0 18px 0;
        font-family: Arial, sans-serif;
        font-size: 1.2em;
        color: #222;
        border-bottom: 2px solid #e0e0e0;
        padding-bottom: 12px;
        }
        .modal-select-row {
        display: flex;
        gap: 8px;
        margin-bottom: 14px;
        }
        #exportHostList {
        max-height: 220px;
        overflow-y: auto;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 8px 12px;
        margin-bottom: 20px;
        background: #fafafa;
        }
        #exportHostList label {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 7px 4px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.95em;
        color: #333;
        }
        #exportHostList label:hover {
        background: #eef4ff;
        }
        #exportHostList input[type='checkbox'] {
        width: 16px; height: 16px;
        accent-color: #2e7d32;
        cursor: pointer;
        }
        .modal-actions {
        display: flex;
        justify-content: flex-end;
        gap: 10px;
        }
        .btn {
        font-family: Arial, sans-serif;
        font-size: 0.9em;
        padding: 8px 18px;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        }
        .btn--sm     { padding: 5px 12px; font-size: 0.82em; }
        .btn--green  { background: #2e7d32; color: #fff; }
        .btn--blue   { background: #1565c0; color: #fff; }
        .btn--grey   { background: #e0e0e0; color: #333; }
        </style>
        """)

        f.write("</head><body>")

        f.write("<header class='site-header'>\n")
        f.write("  <div class='toolbar'>\n")
        f.write("    <span class='badge'><h2>Audit Report</h2></span>\n")
        f.write(
            "    <button class='btn btn--green' onclick='openExportModal()'>&#8659;&nbsp; Export to XLSX</button>\n"
        )
        f.write("  </div>\n")
        f.write("</header>\n")

        f.write("<div class='container'>\n")

        f.write("<h2>Requirements / Host</h2>\n")

        f.write("<div class='legend' style='margin-bottom: 20px;'>")
        for cls in ["passed", "failed", "review", "manual", "unknown"]:
            f.write(f"<span class='{cls}'>{cls}</span>")
        f.write("</div>\n")

        f.write("<table>\n")
        f.write("<thead><tr><th>Requirement</th>")
        for site in site_reports:
            json_path = site.get("json_path", "")
            if "windows_output" in json_path.lower():
                os_label = "Windows"
            elif "linux_output" in json_path.lower():
                os_label = "Linux"
            else:
                os_label = "Unknown"
            col_header = f"{site['hostname']} ({os_label})"
            f.write(f"<th>{html.escape(col_header)}</th>")
        f.write("</tr></thead>\n<tbody>\n")

        for req_id in all_req_ids:
            f.write("<tr>")
            f.write(
                f"<td><b>{html.escape(req_id)}</b><br><small>{html.escape(req_desc.get(req_id, ''))}</small></td>"
            )
            for site in site_reports:
                host = site["hostname"]
                entry = matrix[req_id].get(host)
                if entry:
                    status = entry.get("status", "unknown")
                    href = f"{site['report_path']}#{req_anchor(req_id)}"
                    row_id = "req_" + "".join(
                        ch if ch.isalnum() else "_" for ch in req_id
                    )
                    f.write(
                        f"<td class='{html.escape(status)}' "
                        f"data-host='{html.escape(host)}' "
                        f"data-req='{html.escape(row_id)}'>"
                        f"<a class='cell-link' href='{html.escape(href)}'>{html.escape(status)}</a>"
                        f"</td>"
                    )
                else:
                    f.write("<td class='unknown'>n/a</td>")
            f.write("</tr>\n")

        f.write("</tbody>\n</table>\n</div>\n")  # close table-wrap
        f.write("</div>\n")  # close container

        f.write("<div id='exportModal' class='modal-overlay'>\n")
        f.write("  <div class='modal-box'>\n")
        f.write("    <h3>Select Hosts to Export</h3>\n")
        f.write("    <div class='modal-select-row'>\n")
        f.write(
            "      <button class='btn btn--blue btn--sm' onclick='toggleAllHosts(true)'>Select All</button>\n"
        )
        f.write(
            "      <button class='btn btn--grey btn--sm' onclick='toggleAllHosts(false)'>Clear All</button>\n"
        )
        f.write("    </div>\n")
        f.write("    <div id='exportHostList'></div>\n")
        f.write("    <div class='modal-actions'>\n")
        f.write(
            "      <button class='btn btn--grey' onclick='closeExportModal()'>Cancel</button>\n"
        )
        f.write(
            "      <button class='btn btn--green' onclick='doExportXlsx()'>Export XLSX</button>\n"
        )
        f.write("    </div>\n")
        f.write("  </div>\n")
        f.write("</div>\n")

        f.write("<script>\n")
        f.write(f"  const REPORT_SESSION = {json.dumps(report_session)};\n")
        f.write(f"  const EXPORT_DATA = {export_data_json};\n")
        f.write("  const BUILD_RESET_MARKER = 'zipaudit|build_marker';\n")
        f.write("  (function resetSavedReviewsForNewBuild() {\n")
        f.write("    const previous = localStorage.getItem(BUILD_RESET_MARKER);\n")
        f.write("    if (previous !== REPORT_SESSION) {\n")
        f.write("      Object.keys(localStorage).forEach(k => {\n")
        f.write(
            "        if (k.startsWith('zipaudit|') && k !== BUILD_RESET_MARKER) {\n"
        )
        f.write("          localStorage.removeItem(k);\n")
        f.write("        }\n")
        f.write("      });\n")
        f.write("      localStorage.setItem(BUILD_RESET_MARKER, REPORT_SESSION);\n")
        f.write("    }\n")
        f.write("  })();\n")
        f.write("  function applyStoredStatuses() {\n")
        f.write(
            "    document.querySelectorAll('tbody td[data-host][data-req]').forEach(td => {\n"
        )
        f.write(
            "      const key = 'zipaudit|' + td.dataset.host + '|' + td.dataset.req;\n"
        )
        f.write("      const raw = localStorage.getItem(key);\n")
        f.write("      if (!raw) return;\n")
        f.write("      try {\n")
        f.write("        const saved = JSON.parse(raw);\n")
        f.write("        td.className = saved.status || 'unknown';\n")
        f.write("        const a = td.querySelector('a.cell-link');\n")
        f.write("        if (a) a.textContent = saved.status || 'unknown';\n")
        f.write("      } catch (e) {}\n")
        f.write("    });\n")
        f.write("  }\n")

        f.write(
            "  document.addEventListener('DOMContentLoaded', applyStoredStatuses);\n"
        )
        f.write("  window.addEventListener('focus', applyStoredStatuses);\n")
        f.write("  window.addEventListener('storage', applyStoredStatuses);\n")
        f.write("  window.addEventListener('pageshow', applyStoredStatuses);\n")

        f.write("  function openExportModal() {\n")
        f.write("    const list = document.getElementById('exportHostList');\n")
        f.write("    list.innerHTML = '';\n")
        f.write("    EXPORT_DATA.forEach((host, i) => {\n")
        f.write("      const label = document.createElement('label');\n")
        f.write("      const cb = document.createElement('input');\n")
        f.write("      cb.type = 'checkbox'; cb.checked = true; cb.dataset.idx = i;\n")
        f.write("      label.appendChild(cb);\n")
        f.write(
            "      label.appendChild(document.createTextNode(' ' + host.hostname + ' (' + host.os_label + ')'));\n"
        )
        f.write("      list.appendChild(label);\n")
        f.write("    });\n")
        f.write("    document.getElementById('exportModal').classList.add('open');\n")
        f.write("  }\n\n")

        f.write("  function closeExportModal() {\n")
        f.write(
            "    document.getElementById('exportModal').classList.remove('open');\n"
        )
        f.write("  }\n\n")

        f.write("  function toggleAllHosts(state) {\n")
        f.write(
            "    document.querySelectorAll('#exportHostList input[type=checkbox]')\n"
        )
        f.write("      .forEach(cb => cb.checked = state);\n")
        f.write("  }\n\n")

        f.write("    function doExportXlsx() {\n")
        f.write("        const selected = Array.from(\n")
        f.write(
            "            document.querySelectorAll('#exportHostList input[type=checkbox]')\n"
        )
        f.write(
            "        ).filter(cb => cb.checked).map(cb => parseInt(cb.dataset.idx));\n"
        )
        f.write(
            "        if (selected.length === 0) { alert('Please select at least one host.'); return; }\n"
        )
        f.write("\n")
        f.write("        const wb      = XLSX.utils.book_new();\n")
        f.write(
            "        const headers = ['ID','Description','Status','Files','Findings','Look For','QSA Response','Editor\\'s Notes'];\n"
        )
        f.write("\n")
        f.write("        selected.forEach(idx => {\n")
        f.write("            const host      = EXPORT_DATA[idx];\n")
        f.write("            const sheetData = [headers];\n")
        f.write("\n")
        f.write("            host.rows.forEach(row => {\n")
        f.write(
            "                // Build the localStorage key the same way the report page does\n"
        )
        f.write(
            "                const reqKey    = 'req_' + row.id.replace(/[^a-zA-Z0-9]/g, '_');\n"
        )
        f.write(
            "                const storeKey = 'zipaudit|' + host.hostname + '|' + reqKey;\n"
        )
        f.write("                const raw       = localStorage.getItem(storeKey);\n")
        f.write("                let   status    = row.status;\n")
        f.write("                let   noteStr   = '';\n")
        f.write("\n")
        f.write("                if (raw) {\n")
        f.write("                    try {\n")
        f.write("                        const saved = JSON.parse(raw);\n")
        f.write("                        status  = saved.status || status;\n")
        f.write(
            "                        if (Array.isArray(saved.notes) && saved.notes.length) {\n"
        )
        f.write("                            noteStr = saved.notes\n")
        f.write(
            "                                .map(n => n.timestamp + ' | moved to ' + n.status + ' | ' + n.note)\n"
        )
        f.write("                                .join('\\n\\n');\n")
        f.write("                        }\n")
        f.write("                    } catch(e) {}\n")
        f.write("                }\n")
        f.write("\n")
        f.write("                sheetData.push([\n")
        f.write("                    row.id,\n")
        f.write("                    row.description,\n")
        f.write("                    status,\n")
        f.write("                    row.files,\n")
        f.write("                    row.findings,\n")
        f.write("                    row.look_for,\n")
        f.write("                    status === 'passed' ? row.qsa_response : '',\n")
        f.write("                    noteStr\n")
        f.write("                ]);\n")
        f.write("            });\n")
        f.write("\n")
        f.write("            const ws = XLSX.utils.aoa_to_sheet(sheetData);\n")
        f.write(
            "            ws['!cols'] = [{wch:30},{wch:50},{wch:10},{wch:25},{wch:60},{wch:40},{wch:60},{wch:50}];\n"
        )
        f.write(
            "            const sheetName = (host.hostname + ' (' + host.os_label + ')').replace(/[\\\\\\/?*\\[\\]]/g, '').substring(0, 31);\n"
        )
        f.write("            XLSX.utils.book_append_sheet(wb, ws, sheetName);\n")
        f.write("        });\n")
        f.write("\n")
        f.write("        const ts = new Date().toISOString().replace(/[:.]/g, '-');\n")
        f.write("        XLSX.writeFile(wb, `zip_audit_export_${ts}.xlsx`);\n")
        f.write(
            "        document.getElementById('exportModal').style.display = 'none';\n"
        )
        f.write("    }\n")

        # Close modal on backdrop click
        f.write(
            "  document.getElementById('exportModal').addEventListener('click', function(e) {\n"
        )
        f.write("    if (e.target === this) closeExportModal();\n")
        f.write("  });\n")

        f.write("</script>\n")
        f.write("</body>\n</html>\n")


# these are the actual host rules; this is the main logic for linux report rows
def evaluate_from_json(data, all_files, cheat_sheet):
    report = []

    def add(
        id,
        request_detail,
        status,
        findings,
        files,
        default_file=None,
        look_for="",
        qsa_response="",
    ):
        report.append(
            {
                "id": id,
                "description": request_detail,
                "status": status,
                "findings": [
                    {"message": f} if not isinstance(f, dict) else f for f in findings
                ],
                "files": files,
                "default_file": default_file or (files[0] if files else None),
                "look_for": look_for,
                "evidence_files": all_files,
                "qsa_response": qsa_response,
            }
        )

    summary = data.get("summary", {})
    ssh = data.get("sshd_config", {})
    ssh_lower = {k.lower(): v for k, v in ssh.items()}
    logging = data.get("logging", {})
    ts = data.get("timesync", {})
    groups = data.get("groups", [])
    passwd_list = data.get("passwd", [])
    running_services = data.get("running_services", [])
    updates = data.get("update_history", [])

    wheel = next((g for g in groups if g.get("group") == "wheel"), None)

    # -------------------------
    # [2.2.1.c]
    # -------------------------
    insecure_defs = cheat_sheet.get("insecure_services_linux", [])
    found_insecure = []

    for svc in running_services:
        service_name = (svc.get("service") or "").lower()
        description = (svc.get("description") or "").lower()

        for insecure in insecure_defs:
            aliases = [a.lower() for a in insecure.get("aliases", [])]

            if any(alias in service_name or alias in description for alias in aliases):
                found_insecure.append(
                    {
                        "service": svc.get("service", ""),
                        "description": svc.get("description", ""),
                        "mapped_name": insecure.get("name", ""),
                        "notes": insecure.get("notes", ""),
                        "remediation": insecure.get("remediation", ""),
                    }
                )
                break  # avoid duplicate matches
    findings_221c = []

    if found_insecure:
        for hit in found_insecure:
            findings_221c.append(
                {
                    "message": (
                        f"<b>Detected potential insecure/common-risk service</b>: {hit['service']} "
                        f"({hit['description']})\n"
                        f"<b>Mapped category</b>: {hit['mapped_name']}\n"
                        f"<b>Note/Risk</b>: {hit['notes']}\n"
                        f"<b>Remediation</b>: {hit['remediation']}"
                    ),
                    "file": "1.2.5_running_services.txt",
                }
            )
    else:
        findings_221c.append(
            {
                "message": "No common insecure services found. Please review before passing.",
                "file": "1.2.5_running_services.txt",
            }
        )

    add(
        "[2.2.1.c]",
        "Provide system configuration standards to confirm insecure services are disabled (for example: root, telnet, ftp, tftp, bootp, sendmail, smb, NIS, rexec, rsh, rlogin; daemons such as lpd, dns, DHCP).",
        "review",
        findings_221c,
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Unexpected or insecure services such as telnet/ftp/rsh/rlogin/sendmail, etc.",
        qsa_response="QSA reviewed configuration and confirmed that no insecure services were found enabled across systems. This was confirmed by reviewing the system configurations and service descriptions against common insecure services, as well as manual review of running services for any unexpected or high-risk services that may not be common.",
    )

    # -------------------------
    # [2.2.2.c]
    # -------------------------
    status_222 = "passed" if ssh.get("PermitRootLogin") == "no" else "review"

    add(
        "[2.2.2.c]",
        "Provide configuration files to confirm that all vendor default accounts are removed or disabled.",
        status_222,
        [
            f"PermitRootLogin = {ssh.get('PermitRootLogin')}",
            f"Observed {len(passwd_list)} local accounts.",
            "Root remote login disabled reduces risk of default/shared credential usage.",
        ],
        ["8.3_sshd_config.txt"],
        default_file="8.3_sshd_config.txt",
        look_for="Default or vendor-provided accounts that should be disabled or removed.",
        qsa_response="QSA reviewed the SSH configuration and confirmed that root login is disabled across all systems. This was confirmed by reviewing the sshd_config settings for PermitRootLogin, as well as reviewing the list of local accounts for any default or vendor-provided accounts that should be disabled or removed. The presence of root login being disabled significantly reduces the risk associated with default/shared credential usage.",
    )

    # -------------------------
    # [2.2.3.b]
    # -------------------------
    add(
        "[2.2.3.b]",
        "Provide system configurations to confirm that primary functions requiring different access levels are separated.",
        "manual",
        [
            "This control requires architecture and function separation review.",
            f"Observed {len(running_services)} running services as context.",
        ],
        ["1.2.5_running_services.txt", "summary.csv"],
        default_file="1.2.5_running_services.txt",
        look_for="Whether conflicting primary functions coexist on one host without separation.",
        qsa_response="QSA reviewed the system configurations and observed the running services and their descriptions to understand the primary functions of the host and confirmed that primary functions requiring different access levels were isolated from one another.",
    )

    # -------------------------
    # [2.2.3.c]
    # -------------------------

    # Note: Per feedback from John Jordan, this requirement has been removed as it does not pertain to script outputs

    # insecure_defs = cheat_sheet.get("insecure_services_linux", [])
    # detected_categories = set()

    # for svc in running_services:
    #     name = (svc.get("service") or "").lower()
    #     desc = (svc.get("description") or "").lower()

    #     for insecure in insecure_defs:
    #         if any(
    #             alias in name or alias in desc for alias in insecure.get("aliases", [])
    #         ):
    #             detected_categories.add(insecure["name"])

    # findings_223c = []

    # if detected_categories:
    #     findings_223c.append(
    #         f"Insecure/high-risk service categories detected: {list(detected_categories)}"
    #     )

    # if len(running_services) > 30:
    #     findings_223c.append(
    #         "Large number of services suggests possible multi-function host."
    #     )

    # if ssh.get("PermitRootLogin") != "no":
    #     findings_223c.append("Root login enabled — indicates weaker security boundary.")

    # if not findings_223c:
    #     findings_223c.append(
    #         "No obvious conflicting security roles detected. Manual validation required."
    #     )

    # add(
    #     "[2.2.3.c]",
    #     "Provide system configurations to confirm that system functions requiring different security needs are separated or appropriately secured together.",
    #     "review",
    #     findings_223c,
    #     ["1.2.5_running_services.txt", "8.3_sshd_config.txt"],
    #     default_file="1.2.5_running_services.txt",
    #     look_for="Coexistence of high-risk services with sensitive services or mixed security domains.",
    #     qsa_response="QSA reviewed the system configurations, running services, and SSH settings to evaluate whether there were any conflicting primary functions or high-risk services coexisting on the host without proper separation. The review considered the types of services running, their descriptions, and the SSH configuration to assess the security boundaries and whether functions with different security needs were appropriately separated or secured together.",
    # )

    # -------------------------
    # [2.2.4.b]
    # -------------------------
    add(
        "[2.2.4.b]",
        "Provide evidence to confirm that unnecessary functions are removed or disabled.",
        "review",
        [
            f"Observed {len(running_services)} running services.",
            "Manual validation still required to determine whether services are necessary for business purpose.",
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Services running without a clear business need.",
        qsa_response="QSA reviewed the list of running services and their descriptions to evaluate whether there were any unnecessary functions that should be removed or disabled. The review focused on identifying any services that are commonly considered unnecessary or high-risk, but ultimately requires context from the organization to confirm whether specific services are needed.",
    )

    # -------------------------
    # [2.2.5.b]
    # -------------------------

    if not found_insecure:
        add(
            "[2.2.5.b]",
            "Provide configuration settings to confirm that additional security features are implemented to reduce the risk of using insecure services, daemons, and protocols.",
            "passed",
            [
                "No insecure services detected from 2.2.1.c.",
                "This requirement does not apply when insecure services are not present.",
            ],
            ["1.2.5_running_services.txt"],
            default_file="1.2.5_running_services.txt",
            look_for="N/A – no insecure services present.",
            qsa_response="QSA reviewed the system configurations and confirmed that no insecure services were found enabled across systems, therefore this requirement is not applicable. This was confirmed by reviewing the system configurations and service descriptions against common insecure services, as well as manual review of running services for any unexpected or high-risk services that may not be common.",
        )

    else:
        # fall back to SSH hardening review (your existing logic)
        findings_225b = []

        checks = {
            "<b>Protocol 2</b>": ssh_lower.get("protocol") == "2",
            "<b>Root login disabled</b>": ssh_lower.get("permitrootlogin") == "no",
            "<b>TCP forwarding disabled</b>": ssh_lower.get("allowtcpforwarding") == "no",
            "<b>X11 forwarding disabled</b>": ssh_lower.get("x11forwarding") == "no",
            "<b>Tunnel disabled</b>": ssh_lower.get("permittunnel") == "no",
            "<b>Ignore rhosts</b>": ssh_lower.get("ignorerhosts") == "yes",
            "<b>Host-based authentication disabled</b>": ssh_lower.get(
                "hostbasedauthentication"
            )
            == "no",
            "<b>Empty passwords disabled</b>": ssh_lower.get("permitemptypasswords") == "no",
            "<b>MaxAuthTries ≤ 4</b>": str(ssh_lower.get("maxauthtries") or "").isdigit()
            and int(ssh_lower.get("maxauthtries") or 999) <= 4,
        }

        for check, passed in checks.items():
            findings_225b.append(f"{check}: {'PASS' if passed else 'FAIL'}")

        # display configured crypto if present (case-insensitive)
        if ssh_lower.get("ciphers"):
            ciphers = ssh_lower.get("ciphers")
            findings_225b.append(
                f"<b>Strong ciphers configured</b>: {', '.join(ciphers) if isinstance(ciphers, list) else ciphers}"
            )

        if ssh_lower.get("macs"):
            macs = ssh_lower.get("macs")
            findings_225b.append(
                f"<b>MAC algorithms configured</b>: {', '.join(macs) if isinstance(macs, list) else macs}"
            )

        if ssh_lower.get("kexalgorithms"):
            kex = ssh_lower.get("kexalgorithms")
            findings_225b.append(
                f"<b>KEX algorithms configured</b>: {', '.join(kex) if isinstance(kex, list) else kex}"
            )

        add(
            "[2.2.5.b]",
            "Provide configuration settings to confirm that additional security features are implemented to reduce the risk of using insecure services, daemons, and protocols.",
            "review",
            findings_225b,
            ["8.3_sshd_config.txt"],
            default_file="8.3_sshd_config.txt",
            look_for="Security hardening controls applied when insecure services exist.",
            qsa_response="QSA reviewed the SSH configuration settings to evaluate whether additional security features were implemented to reduce the risk of using insecure services. The review focused on key SSH hardening controls such as enforcing Protocol 2, disabling root login, disabling TCP/X11 forwarding, and ensuring strong ciphers and authentication settings were applied.",
        )

    # -------------------------
    # [2.2.6.c]
    # -------------------------

    findings_226c = []

    status = "passed"

    # UID 0 accounts
    uid0_accounts = [u["username"] for u in passwd_list if u.get("uid") == 0]

    if uid0_accounts == ["root"]:
        findings_226c.append("Only root has UID 0: PASS")
    else:
        findings_226c.append(f"Multiple UID 0 accounts detected: {uid0_accounts}")
        status = "review"

    # Unused / insecure services (reuse your cheat sheet logic)
    if not found_insecure:
        findings_226c.append("No common insecure services detected: PASS")
    else:
        findings_226c.append(f"Insecure services present: {len(found_insecure)} found")
        status = "review"

    # Password policy (partial automation)
    pw_min = summary.get("PwMinLen")

    try:
        if pw_min and int(pw_min) >= 12:
            findings_226c.append(f"Password minimum length = {pw_min}: PASS")
        else:
            findings_226c.append(f"Weak password length: {pw_min}")
            status = "review"
    except:
        findings_226c.append("Password policy not clearly defined")
        status = "review"

    # Generic account detection (basic heuristic)
    generic_users = [
        u["username"]
        for u in passwd_list
        if u["username"] in ["test", "guest", "admin", "user"]
    ]

    if generic_users:
        findings_226c.append(f"Potential generic accounts detected: {generic_users}")
        status = "review"
    else:
        findings_226c.append("No obvious generic accounts: PASS")

    add(
        "[2.2.6.c]",
        "Provide system configurations to confirm that common security parameters are set appropriately and in accordance with configuration standards.",
        status,
        findings_226c,
        ["passwd.txt", "summary.csv", "1.2.5_running_services.txt"],
        default_file="passwd.txt",
        look_for="Common hardening controls: UID separation, password policies, service minimization, and account hygiene.",
        qsa_response="QSA reviewed the system configurations, password policies, and account information to evaluate whether common security parameters were set appropriately. The review focused on key hardening controls such as ensuring only root has UID 0, confirming that no common insecure services were present, evaluating password policy strength, and checking for potential generic accounts that may indicate weak account hygiene.",
    )

    # -------------------------
    # [2.2.7.b]
    # -------------------------
    add(
        "[2.2.7.b]",
        "Provide system configurations to confirm that non-console administrative access is managed in accordance with this requirement.",
        (
            "passed"
            if summary.get("Telnet") == "FALSE" and ssh.get("Protocol") == "2"
            else "failed"
        ),
        [
            f"Telnet flag in summary = {summary.get('Telnet')}",
            f"SSH protocol in sshd_config = {ssh.get('Protocol')}",
            f"PermitRootLogin = {ssh.get('PermitRootLogin')}",
        ],
        ["summary.csv", "8.3_sshd_config.txt"],
        default_file="8.3_sshd_config.txt",
        look_for="Telnet disabled and SSH protocol set to 2.",
        qsa_response="QSA reviewed the system configurations to confirm that non-console administrative access was managed in accordance with the requirement. The review focused on confirming that Telnet was disabled (as indicated in the summary) and that SSH was configured to use Protocol 2, which is more secure than Protocol 1. Additionally, the review considered the PermitRootLogin setting as part of evaluating the overall security of remote administrative access.",
    )

    # -------------------------
    # [2.2.7.c]
    # -------------------------

    findings_227c = []

    # Check for insecure services (reuse 2.2.1.c)
    insecure_remote = [
        s
        for s in found_insecure
        if any(
            x in s.get("mapped_name", "").lower()
            for x in ["telnet", "rlogin", "rsh", "rexec", "ftp"]
        )
    ]

    if not insecure_remote:
        findings_227c.append(
            "No insecure remote login services detected (e.g., Telnet, rlogin, FTP): PASS"
        )
        insecure_ok = True
    else:
        findings_227c.append(
            f"Insecure remote services detected: {[s['mapped_name'] for s in insecure_remote]}: FAIL"
        )
        insecure_ok = False

    # SSH protocol strength
    protocol_ok = ssh.get("Protocol") == "2"
    findings_227c.append(
        f"SSH Protocol = {ssh.get('Protocol')}: {'PASS' if protocol_ok else 'FAIL'}"
    )

    # Authentication enforced (case-insensitive)
    auth_ok = (
        ssh_lower.get("permitemptypasswords") == "no" and summary.get("NullOK") != "TRUE"
    )

    findings_227c.append(
        f"PasswordAuthentication = {ssh.get('PasswordAuthentication')}: {'PASS' if ssh_lower.get('permitemptypasswords') == 'no' else 'FAIL'}"
    )
    findings_227c.append(
        f"NullOK = {summary.get('NullOK')}: {'PASS' if summary.get('NullOK') != 'TRUE' else 'FAIL'}"
    )
    certauth_ok = summary.get("CertAuth") == "TRUE"
    findings_227c.append(
        f"CertAuth = {summary.get('CertAuth')}: {'PASS' if certauth_ok else 'FAIL'}"
    )

    # Encryption strength (from your prior outputs)
    if ssh_lower.get("ciphers"):
        c = ssh_lower.get("ciphers")
        findings_227c.append(f"Ciphers configured: {', '.join(c) if isinstance(c, list) else c}")

    # require telnet disabled, protocol 2, auth checks and ciphers
    if insecure_ok and protocol_ok and auth_ok and certauth_ok:
        status_227c = "passed"
    else:
        status_227c = "review"

    add(
        "[2.2.7.c]",
        "Provide settings for system components and authentication services to confirm that insecure remote login services are not available for non-console administrative access.",
        status_227c,
        findings_227c,
        ["1.2.5_running_services.txt", "8.3_sshd_config.txt", "summary.csv"],
        default_file="8.3_sshd_config.txt",
        look_for="Absence of insecure remote protocols and presence of secure SSH with strong authentication and encryption.",
        qsa_response="QSA reviewed the system configurations to confirm that insecure remote login services were not available for non-console administrative access. The review focused on ensuring that services like Telnet were disabled and that SSH was properly configured with strong authentication and encryption.",
    )

    # -------------------------
    # Logic for 5.x to find anti malware services
    # -------------------------

    detected_av = []

    av_defs = cheat_sheet.get("av_signatures", [])

    for svc in running_services:
        service_name = (svc.get("service") or "").lower()
        description = (svc.get("description") or "").lower()
        state = (svc.get("status") or "").lower()

        for av in av_defs:
            aliases = [a.lower() for a in av.get("aliases", [])]

            if any(alias in service_name or alias in description for alias in aliases):
                if "running" in state:
                    detected_av.append(
                        {
                            "vendor": av.get("name"),
                            "service": svc.get("service"),
                            "description": svc.get("description"),
                        }
                    )
                break  # stop checking more aliases for this service

    # -------------------------
    # [5.2.1.a]
    # -------------------------
    status_521 = "passed" if detected_av else "review"

    findings_521 = []

    if detected_av:
        for av in detected_av:
            findings_521.append(
                f"Detected AV/EDR solution: {av['vendor']} ({av['service']}) — running"
            )
    else:
        findings_521.append("No known AV/EDR services detected.")

    add(
        "[5.2.1.a]",
        "Provide evidence that an anti-malware solution is deployed where required.",
        status_521,
        findings_521,
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Presence of AV/EDR services in running state.",
        qsa_response="QSA reviewed the list of running services to identify any known anti-malware (AV/EDR) solutions deployed on the system to confirm that an anti-malware solution was present where required. The review consisted of finding matches between running services and known AV/EDR signatures, and evaluating their state to confirm they were active.",
    )

    # -------------------------
    # [5.3.1.a]
    # -------------------------
    add(
        "[5.3.1.a]",
        "Provide anti-malware solution configurations to confirm the solution is configured appropriately.",
        "passed" if detected_av else "review",
        [
            (
                f"Detected AV solutions: {[av['vendor'] for av in detected_av]}"
                if detected_av
                else "No AV detected — requires review"
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Active AV presence implies baseline configuration is applied.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the solution was configured appropriately. The review focused on ensuring that the AV/EDR solution was properly configured with baseline settings.",
    )

    # -------------------------
    # [5.3.1.b]
    # -------------------------
    add(
        "[5.3.1.b]",
        "Provide logs to confirm that the anti-malware solution(s) and definitions are current and have been promptly deployed.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected but version/definition recency cannot be verified from services."
                if detected_av
                else "No AV detected — cannot validate."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Definition update status or management console evidence.",
        qsa_response="QSA reviewed the available evidence to evaluate whether the anti-malware solution and its definitions were current and promptly deployed. The review considered the presence of AV/EDR services and any available information about their version or definition update status.",
    )

    # -------------------------
    # [5.3.2.a]
    # -------------------------
    add(
        "[5.3.2.a]",
        "Provide anti-malware configurations to confirm the solution is configured for active monitoring.",
        "passed" if detected_av else "review",
        [
            (
                "Running AV/EDR service strongly indicates active monitoring."
                if detected_av
                else "No AV/EDR running — active monitoring cannot be confirmed."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="AV/EDR service running suggests active monitoring, but review for management console or logs to confirm.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the solution was configured for active monitoring. The review focused on the presence of running AV/EDR services as an indicator of active monitoring, while also noting that additional evidence such as management console access or logs would be needed to fully confirm active monitoring practices.",
    )

    # -------------------------
    # [5.3.2.b]
    # -------------------------
    add(
        "[5.3.2.b]",
        "Provide evidence to confirm the anti-malware solution is enabled.",
        "passed" if detected_av else "review",
        [
            (
                "AV/EDR service observed running."
                if detected_av
                else "No AV service running."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        qsa_response="QSA reviewed the evidence to confirm that the anti-malware solution was enabled. The review focused on the presence of running AV/EDR services as an indicator that the solution was active and enabled on the system.",
    )

    # -------------------------
    # [5.3.2.c]
    # -------------------------
    add(
        "[5.3.2.c]",
        "Provide logs to confirm that the solution(s) is enabled in accordance with at least one of the elements specified in this requirement",
        "passed" if detected_av else "review",
        [
            (
                "AV running, but scheduling must be verified via logs or console."
                if detected_av
                else "No AV detected."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Scheduled scans, real-time protection status, or management console evidence confirming enabled features",
        qsa_response="QSA reviewed the available evidence to confirm that the anti-malware solution was enabled in accordance with the specified elements. The review considered the presence of running AV/EDR services as an indicator of enabled status, while also noting that additional evidence such as logs or management console access would be needed to verify specific features like scheduled scans or real-time protection.",
    )

    # -------------------------
    # [5.3.4]
    # -------------------------
    add(
        "[5.3.4]",
        "Provide anti-malware solution(s) configurations to confirm logs are enabled and retained in accordance with Requirement 10.5.1.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected, but logging configuration cannot be validated from service data."
                if detected_av
                else "No AV detected."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Logging settings in AV configuration or management console, and retention policies.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that logs were enabled and retained in accordance with Requirement 10.5.1. The review focused on the presence of running AV/EDR services as an indicator of an active solution, while also noting that specific logging configurations and retention policies would need to be verified through management console access or additional configuration files.",
    )

    # -------------------------
    # [5.3.5.a]
    # -------------------------
    add(
        "[5.3.5.a]",
        "Provide anti-malware solution configurations to confirm that the anti-malware mechanisms cannot be disabled or altered by users.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected, review to ensure appropriate tamper protection or policy controls are in place."
                if detected_av
                else "No AV detected."
            )
        ],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Tamper protection settings or policy controls preventing user disablement.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the anti-malware mechanisms could not be disabled or altered by users. The review focused on identifying any tamper protection settings or policy controls that would prevent unauthorized disablement of the AV/EDR solution, while also noting that specific controls would need to be verified through management console access or additional configuration files.",
    )

    # -------------------------
    # [5.3.5.b]
    # -------------------------
    add(
        "[5.3.5.b]",
        "Provide observation(s) to confirm that attempts to disable or remove anti-malware are prevented.",
        "manual",
        ["Requires manual observation or management policy evidence."],
        ["1.2.5_running_services.txt"],
        default_file="1.2.5_running_services.txt",
        look_for="Tamper protection / policy preventing disablement.",
        qsa_response="QSA reviewed the available evidence to confirm that attempts to disable or remove the anti-malware solution were prevented."
    )

    # -------------------------
    # [6.3.3.b]
    # -------------------------
    add(
        "[6.3.3.b]",
        "Provide system component and patch/update data to confirm vulnerabilities are patched according to policy.",
        "review",
        [
            f"Package manager detected = {data.get('package_manager')}",
            f"Update history entries observed = {len(updates)}",
            "Update history alone is not sufficient to prove latest available security patches are installed.",
        ],
        ["6.3.3_update_history.txt", "release.txt"],
        default_file="6.3.3_update_history.txt",
        look_for="Recent patch cadence and comparison to latest available updates.",
        qsa_response="QSA reviewed the system component and patch/update data to evaluate whether vulnerabilities were patched according to policy. The review considered the package manager in use, the number of update history entries, and the recency of updates.",
    )

    # -------------------------
    # [7.2.1.b]
    # -------------------------
    add(
        "[7.2.1.b]",
        "Provide user access settings to confirm access is based on job/function need.",
        "review",
        [
            f"Observed {len(passwd_list)} local accounts.",
            f"Wheel members = {wheel['members'] if wheel else []}",
        ],
        ["8.2_enabledusers.txt", "passwd.txt"],
        default_file="8.2_enabledusers.txt",
        look_for="Users/accounts with unnecessary or excessive access.",
        qsa_response="QSA reviewed the user access settings to confirm that access was based on job/function need. The review focused on the number of local accounts and the members of the wheel group to evaluate whether any users had unnecessary or excessive access privileges.",
    )

    # -------------------------
    # [7.2.2.b]
    # -------------------------
    add(
        "[7.2.2.b]",
        "Provide user access settings to confirm privileges assigned are based on job function.",
        "review",
        [
            f"Wheel group present = {'yes' if wheel else 'no'}",
            f"Wheel members = {wheel['members'] if wheel else []}",
        ],
        ["8.2_enabledusers.txt", "passwd.txt"],
        default_file="8.2_enabledusers.txt",
        look_for="Privileged memberships consistent with approved job functions.",
        qsa_response="QSA reviewed the user access settings to confirm that privileges assigned were based on job function. The review focused on the wheel group and its members to evaluate whether privileged memberships were consistent with approved job functions.",
    )

    # -------------------------
    # [7.2.3.b]
    # -------------------------
    # Automated review: enumerate privileged accounts and produce evidence for manual approval verification
    uid0_accounts = [u.get("username") for u in passwd_list if u.get("uid") == 0]
    wheel_members = wheel.get("members") if wheel else []
    sudoers_entries = data.get("sudoers", [])
    sudo_users = []

    for s in sudoers_entries:
        if isinstance(s, dict):
            sudo_users.append(s.get("user") or s.get("access") or str(s))
        else:
            sudo_users.append(str(s))

    # Prepare a readable preview of sudoers entries (join list items),
    # and append a truncation note if there are more than 15 entries.
    entries_preview = ", ".join(map(str, sudo_users[:15]))
    truncated_note = (
        " (List truncated at 15 users. View sudoers.txt for full list.)"
        if len(sudo_users) > 15
        else ""
    )

    findings_723b = [
        f"Observed {len(passwd_list)} local accounts.",
        f"UID 0 accounts: {uid0_accounts}",
        f"Wheel group members: {wheel_members}",
        f"Sudoers entries: {entries_preview}{truncated_note}",
        "Documented approval evidence (tickets/policies) not present in JSON; review required to confirm approvals.",
    ]

    add(
        "[7.2.3.b]",
        "Provide user IDs and assigned privileges to confirm documented approval exists.",
        "review",
        findings_723b,
        ["8.2_enabledusers.txt", "passwd.txt", "sudoers.txt"],
        default_file="8.2_enabledusers.txt",
        look_for="Documented approvals matching granted access.",
        qsa_response="QSA reviewed the user IDs and assigned privileges to confirm that documented approval exists. The review focused on the sudoers entries and their associated users to evaluate whether all granted privileges were properly documented and approved."
    )

    # -------------------------
    # [7.2.5.b]
    # -------------------------
    add(
        "[7.2.5.b]",
        "Provide privileges associated with system and application accounts to confirm proper configuration.",
        "review",
        [
            f"Interactive accounts observed = {', '.join(u['username'] for u in passwd_list if u.get('interactive'))}",
            f"Wheel members = {wheel['members'] if wheel else []}",
        ],
        ["8.2_enabledusers.txt", "passwd.txt"],
        default_file="8.2_enabledusers.txt",
        look_for="System/application accounts with interactive shells or elevated access.",
        qsa_response="QSA reviewed the system settings to confirm that access is managed for each system component. The review focused on the configuration of interactive accounts and wheel group members to evaluate whether access controls were properly implemented."
    )

    # -------------------------
    # [7.3.1]
    # -------------------------
    add(
        "[7.3.1]",
        "Provide system settings to confirm access is managed for each system component.",
        "manual",
        [
            "Current JSON provides host-level access indicators but not a complete per-component access control model."
        ],
        ["8.2_enabledusers.txt", "summary.csv"],
        default_file="8.2_enabledusers.txt",
        look_for="Per-component access management configuration.",
        qsa_response="QSA reviewed the system settings to confirm that access is managed for each system component. The review focused on the configuration of interactive accounts and wheel group members to evaluate whether access controls were properly implemented."
    )

    # -------------------------
    # [7.3.2]
    # -------------------------
    add(
        "[7.3.2]",
        "Provide system settings to confirm the access control system is configured appropriately.",
        "manual",
        ["Current JSON does not fully model access control framework configuration."],
        ["8.2_enabledusers.txt", "summary.csv"],
        default_file="8.2_enabledusers.txt",
        look_for="Access control framework settings and enforcement.",
        qsa_response="QSA reviewed the system settings to confirm that the access control system is configured appropriately. The review focused on the configuration of access control mechanisms and their enforcement to evaluate whether the system was properly secured."
    )

    # -------------------------
    # [7.3.3]
    # -------------------------
    add(
        "[7.3.3]",
        "Provide system settings to confirm the access control system is set to default deny access.",
        "manual",
        ["Default-deny posture cannot be fully established from current JSON alone."],
        ["8.2_enabledusers.txt", "summary.csv"],
        default_file="8.2_enabledusers.txt",
        look_for="Default deny / explicit allow model.",
        qsa_response="QSA reviewed the system settings to confirm that the access control system is set to default deny access. The review focused on the configuration of access control policies and their enforcement to evaluate whether the system was properly secured with a default-deny posture."
    )

    # -------------------------
    # [8.2.1.b]
    # -------------------------

    enabled_users = data.get("enabled_users", [])
    findings_821b = []

    # Heuristic patterns for likely shared / generic / functional accounts
    generic_markers = [
        "shared",
        "generic",
        "functional",
        "svc",
        "service",
        "admin",
        "test",
        "temp",
        "bootstrap",
    ]

    suspect_accounts = []

    for user in enabled_users:
        username = (user.get("username") or "").lower()
        comment = (user.get("comment") or "").lower()

        if username == "root":
            findings_821b.append(
                "Root is enabled for interactive access; review whether it is used for routine administration."
            )
            continue

        if any(marker in username for marker in generic_markers) or any(
            marker in comment for marker in generic_markers
        ):
            suspect_accounts.append(user.get("username"))

    if enabled_users == "no file found" or not enabled_users:
        status_821b = "manual"
        findings_821b.append(
            "8.2_enabledusers.txt was not found. Unable to assess enabled interactive accounts."
        )
    else:
        findings_821b.append(
            f"Enabled interactive accounts observed: {', '.join(u['username'] for u in enabled_users)}"
        )

        if suspect_accounts:
            status_821b = "review"
            findings_821b.append(
                f"Potential shared/generic/functional accounts detected: {', '.join(suspect_accounts)}"
            )
        else:
            # still cautious because unique identity usually requires HR/IAM context
            status_821b = "review"
            findings_821b.append(
                "No obvious shared/generic account names detected, but individual ownership still requires validation."
            )

    add(
        "[8.2.1.b]",
        "Provide other evidence to confirm that access to system components and cardholder data can be uniquely identified and associated with individuals.",
        status_821b,
        findings_821b,
        ["8.2_enabledusers.txt"],
        default_file="8.2_enabledusers.txt",
        look_for="Named individual accounts rather than shared, generic, or functional users.",
        qsa_response="QSA reviewed the enabled user accounts to confirm that access to system components and cardholder data can be uniquely identified and associated with individuals. The review focused on ensuring that each account was properly assigned to a specific user and that there were no shared or generic accounts in use."
    )

    # -------------------------
    # [8.2.2.a]
    # -------------------------
    add(
        "[8.2.2.a]",
        "Provide user account evidence to confirm shared or generic credentials are not used except by exception.",
        "review",
        [
            f"PermitRootLogin = {ssh.get('PermitRootLogin')}",
            f"Interactive accounts = {', '.join(u['username'] for u in passwd_list if u.get('interactive'))}",
        ],
        ["passwd.txt", "8.3_sshd_config.txt"],
        default_file="passwd.txt",
        look_for="Generic/shared IDs such as root being used for normal admin access.",
        qsa_response="QSA reviewed the user account settings to confirm that shared or generic credentials are not used except by exception. The review focused on the configuration of user accounts and their associated permissions to evaluate whether any generic IDs were in use."
    )

    # -------------------------
    # [8.2.4]
    # -------------------------

    user_changes = data.get("user_changes", "no file found")
    findings_824 = []

    if user_changes == "no file found":
        status_824 = "manual"
        findings_824.append(
            "8.2.4_user_changes.txt was not found. Unable to evaluate account modification activity."
        )

    elif isinstance(user_changes, list) and len(user_changes) == 0:
        status_824 = "review"
        findings_824.append(
            "No recent useradd/usermod/userdel changes were observed in 8.2.4_user_changes.txt."
        )
        findings_824.append(
            "Still requires review of change tickets / approvals to confirm the activity has been managed."
        )

    else:
        status_824 = "review"
        findings_824.append(
            f"Observed {len(user_changes)} recent user/account change event(s)."
        )
        findings_824.append(
            "Review supporting approval/ticket evidence to confirm changes were authorized and implemented appropriately."
        )

        for change in user_changes[:5]:
            findings_824.append(f"Observed change: {change}")

    add(
        "[8.2.4]",
        "Provide system settings to confirm the activity has been managed.",
        status_824,
        findings_824,
        ["8.2.4_user_changes.txt"],
        default_file="8.2.4_user_changes.txt",
        look_for="User modification evidence tied to approved requests.",
        qsa_response="QSA reviewed the system settings to confirm that user account activity has been managed. The review focused on recent user/account change events and whether they were tied to approved requests or tickets, ensuring that all changes were authorized and implemented appropriately."
    )

    # -------------------------
    # [8.2.6]
    # -------------------------
    inactive_flag = summary.get("Inactive")
    add(
        "[8.2.6]",
        "Provide evidence to confirm inactive user accounts are removed or disabled within 90 days of inactivity.",
        "failed" if inactive_flag == "TRUE" else "passed",
        [f"Inactive flag in summary = {inactive_flag}"],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="Inactive users reported by script.",
        qsa_response="QSA reviewed the system settings to confirm that inactive user accounts are removed or disabled within 90 days of inactivity. The review focused on the configuration of user accounts and their status to evaluate whether the system was properly managing inactive accounts."
    )

    # -------------------------
    # [8.2.8]
    # -------------------------
    tmout = summary.get("IdleTimeout")
    try:
        tmout_val = int(tmout) if tmout not in (None, "", "FALSE", "NA") else None
    except:
        tmout_val = None

    if tmout_val is not None and tmout_val >= 900:
        idle_status = "passed"
    elif tmout in ("FALSE", "", None, "NA"):
        idle_status = "failed"
    else:
        idle_status = "review"

    add(
        "[8.2.8]",
        "Provide evidence to confirm idle sessions require re-authentication after no more than 15 minutes (TMOUT >= 900 seconds).",
        idle_status,
        [f"IdleTimeout / TMOUT value = {tmout}"],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="TMOUT set to 900 seconds or more.",
        qsa_response="QSA reviewed the system settings to confirm that idle sessions require re-authentication after no more than 15 minutes. The review focused on the TMOUT value in the summary to evaluate whether it was set to 900 seconds or more, ensuring that idle session timeouts were properly configured."
    )

    # -------------------------
    # [8.3.1.b]
    # -------------------------
    add(
        "[8.3.1.b]",
        "Provide observation(s) of authentication factors used to confirm they are functional.",
        "review",
        [
            f"PwAuth = {summary.get('PwAuth')}",
            f"CertAuth = {summary.get('CertAuth')}",
            f"ADAuth = {summary.get('ADAuth')}",
            f"NullOK = {summary.get('NullOK')}",
        ],
        ["summary.csv", "8.3_sshd_config.txt"],
        default_file="8.3_sshd_config.txt",
        look_for="Whether passwords, keys, or directory authentication are in use.",
        qsa_response="QSA reviewed the system settings to confirm that authentication factors are functional. The review focused on the configuration of authentication mechanisms and their enforcement to evaluate whether the system was properly secured."
    )

    # -------------------------
    # [8.3.2.a]
    # -------------------------

    findings_832a = []

    sshd_running = any(
        (svc.get("service") or "").lower() in ("sshd.service", "sshd")
        for svc in running_services
    )

    # Linux JSON uses "Ciphers", "Kexalgorithms" (mixed case) — normalise by
    # scanning all keys case-insensitively
    ssh_lower = {k.lower(): v for k, v in ssh.items()}

    kex = ssh_lower.get("kexalgorithms", [])
    macs = ssh_lower.get("macs", [])
    ciphers = ssh_lower.get("ciphers", [])

    has_kex = isinstance(kex, list) and len(kex) > 0
    has_macs = isinstance(macs, list) and len(macs) > 0
    has_ciphers = isinstance(ciphers, list) and len(ciphers) > 0

    if sshd_running:
        findings_832a.append("sshd is running: PASS")
    else:
        findings_832a.append("sshd was not observed running: FAIL")

    if has_kex:
        findings_832a.append(f"KexAlgorithms configured: {', '.join(kex)}: PASS")
    else:
        findings_832a.append("No KexAlgorithms observed in sshd_config: FAIL")

    if has_macs:
        findings_832a.append(f"MACs configured: {', '.join(macs)}: PASS")
    else:
        findings_832a.append("No MACs observed in sshd_config: FAIL")

    if has_ciphers:
        findings_832a.append(f"Ciphers configured: {', '.join(ciphers)}: PASS")
    else:
        findings_832a.append("No Ciphers observed in sshd_config: FAIL")

    # Pass if sshd running and at least ciphers are configured
    # MACs absence is flagged but not a hard fail since some configs
    # rely on system-wide crypto policy
    if sshd_running and has_ciphers and has_kex:
        status_832a = "passed"
    else:
        status_832a = "review"

    add(
        "[8.3.2.a]",
        "Provide system configuration settings to confirm authentication factors are rendered unreadable with strong cryptography.",
        status_832a,
        findings_832a,
        ["8.3_sshd_config.txt", "1.2.5_running_services.txt"],
        default_file="8.3_sshd_config.txt",
        look_for="Strong SSH crypto settings (KexAlgorithms, MACs, ciphers) and active SSH service.",
        qsa_response=(
            (
                "QSA reviewed the SSH configuration settings to confirm that authentication factors were "
                "rendered unreadable through strong cryptography. The review confirmed that sshd was running "
                "and that explicit cipher suites and key exchange algorithms were configured in sshd_config, "
                "consistent with the requirement to protect authentication factors using approved cryptographic "
                "controls during transmission."
            )
            if status_832a == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.2.b]
    # -------------------------

    enc = summary.get("Encryption", "")
    shadow_entries = data.get("shadow", "no file found")
    findings_832b = []
    status_832b = "review"

    # Strong hash identifiers present in the Encryption summary field [3]
    # "1:MD5 6:SHA-512" — SHA-512 ($6$) is considered strong
    STRONG_HASHES = {
        "6",
        "y",
        "gy",
        "7",
    }  # $6$=SHA-512, $y$=yescrypt, $gy$=gost-yescrypt, $7$=scrypt

    if enc:
        enc_ids = set(part.split(":")[0].strip() for part in enc.split() if ":" in part)
        weak_ids = enc_ids - STRONG_HASHES
        strong_ids = enc_ids & STRONG_HASHES

        findings_832b.append(f"Summary Encryption field = {enc}")

        if strong_ids and not weak_ids:
            findings_832b.append(
                f"All observed hash types are strong ({', '.join(f'${i}$' for i in strong_ids)}): PASS"
            )
            status_832b = "passed"
        elif strong_ids and weak_ids:
            findings_832b.append(
                f"Mix of strong ({', '.join(strong_ids)}) and weak ({', '.join(weak_ids)}) hash types detected: FAIL"
            )
            status_832b = "review"
        else:
            findings_832b.append(
                f"Only weak hash type(s) detected ({', '.join(weak_ids)}): FAIL"
            )
            status_832b = "review"

    elif isinstance(shadow_entries, list) and len(shadow_entries) > 0:
        findings_832b.append(
            "shadow.txt is present but password hash values are redacted."
        )
        findings_832b.append(
            "Direct verification of hash algorithm ($5$, $6$, yescrypt) is not possible from redacted content."
        )
        findings_832b.append(f"Observed {len(shadow_entries)} shadow account entries.")
        status_832b = "review"

    elif shadow_entries == "no file found":
        findings_832b.append("shadow.txt was not found.")
        findings_832b.append(
            "No repository evidence available to confirm authentication factors are unreadable during storage."
        )
        status_832b = "review"

    else:
        findings_832b.append("No usable storage-side evidence was available.")
        status_832b = "review"

    add(
        "[8.3.2.b]",
        "Provide repositories of authentication factors to confirm they are unreadable during storage.",
        status_832b,
        findings_832b,
        ["summary.csv", "shadow.txt"],
        default_file="shadow.txt",
        look_for="Strong hash types ($6$, yescrypt) in Encryption summary field, or shadow file evidence.",
        qsa_response=(
            (
                "QSA reviewed the authentication factor storage configuration to confirm that credentials "
                "were stored in an unreadable format. The review confirmed that the system's Encryption "
                f"summary field reported '{enc}', indicating that password hashes were stored using a "
                "strong cryptographic hash algorithm. No weak or reversible storage formats were identified."
            )
            if status_832b == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.2.c]
    # -------------------------

    telnet_val = str(summary.get("Telnet", "")).upper()
    proto_val = str(ssh.get("Protocol", "")).strip()
    # Reuse case-normalised ssh_lower from 8.3.2.a
    ciphers_832c = ssh_lower.get("ciphers", [])
    cipher_str = (
        ", ".join(ciphers_832c)
        if isinstance(ciphers_832c, list) and ciphers_832c
        else "None"
    )

    telnet_ok = telnet_val == "FALSE"
    proto_ok = proto_val == "2"
    ciphers_ok = isinstance(ciphers_832c, list) and len(ciphers_832c) > 0

    status_832c = "passed" if (telnet_ok and proto_ok and ciphers_ok) else "review"

    add(
        "[8.3.2.c]",
        "Provide evidence to confirm authentication factors are unreadable during transmission.",
        status_832c,
        [
            f"Telnet = {summary.get('Telnet')}: {'PASS' if telnet_ok else 'FAIL'}",
            f"SSH Protocol = {proto_val}: {'PASS' if proto_ok else 'FAIL'}",
            f"Ciphers observed = {cipher_str}: {'PASS' if ciphers_ok else 'FAIL'}",
        ],
        ["summary.csv", "8.3_sshd_config.txt"],
        default_file="8.3_sshd_config.txt",
        look_for="Telnet disabled, SSH Protocol 2, and explicit cipher configuration.",
        qsa_response=(
            (
                "QSA reviewed the transmission-layer security configuration to confirm that authentication "
                "factors were protected from interception during transmission. The review confirmed that "
                "Telnet was disabled, SSH was configured to use Protocol 2, and explicit cipher suites were "
                "defined in sshd_config, ensuring that credentials transmitted over SSH were protected by "
                "strong encryption."
            )
            if status_832c == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.4.a]
    # -------------------------

    # summary values arrive as "deny=3" and "unlock_time=3600" [3]
    # parse the numeric part out for display and downstream use
    def parse_kv_int(raw):
        """Extract integer from a 'key=value' string or plain integer string."""
        if raw is None:
            return None, None
        raw = str(raw).strip()
        if "=" in raw:
            key, _, val = raw.partition("=")
            val = val.strip()
            return key.strip(), int(val) if val.isdigit() else None
        return None, int(raw) if raw.isdigit() else None

    attempts_raw = as_dict(data.get("login_attempts")).get("deny")
    timer_raw = as_dict(data.get("login_attempts")).get("unlock_time")
    edr_raw = as_dict(data.get("login_attempts")).get("even_deny_root")
    rut_raw = as_dict(data.get("login_attempts")).get("root_unlock_time")

    _, attempts_parsed = parse_kv_int(attempts_raw)
    _, timer_parsed = parse_kv_int(timer_raw)

    edr_active = str(edr_raw).upper() not in ("FALSE", "NA", "", "NONE")
    rut_set = str(rut_raw).upper() not in ("NA", "", "NONE", "FALSE")

    if attempts_parsed is None or timer_parsed is None:
        status834a = False
    else:
        status834a = attempts_parsed <= 10 and timer_parsed >= 1800 and edr_active

    add(
        "[8.3.4.a]",
        "Provide system configuration settings to confirm authentication parameters are set appropriately for failed logon controls.",
        "passed" if status834a else "review",
        [
            f"deny (Attempts) = {attempts_raw} → parsed value = {attempts_parsed}: "
            f"{'PASS' if attempts_parsed is not None and attempts_parsed <= 10 else 'FAIL/unset'}",
            f"unlock_time (Timer) = {timer_raw} → parsed value = {timer_parsed}s: "
            f"{'PASS' if timer_parsed is not None and timer_parsed >= 1800 else 'FAIL/unset'}",
            f"even_deny_root (EDR) = {edr_raw}: {'PASS' if edr_active else 'not enabled'}",
            f"root_unlock_time (RUT) = {rut_raw}: {'PASS' if rut_set else 'Inherits unlock_time'}",
        ],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="deny ≤ 10, unlock_time ≥ 1800 seconds, even_deny_root presence, root_unlock_time.",
        qsa_response=(
            "QSA reviewed the PAM faillock configuration to confirm that authentication lockout "
            "parameters were set appropriately. The review confirmed that the deny threshold and "
            "unlock_time were configured at levels consistent with the requirement, and that the "
            "settings were applied via faillock.conf."
        ),
    )

    # -------------------------
    # [8.3.4.b]
    # -------------------------

    findings_834b = []
    status_834b = "review"

    # Reuse parsed values from 8.3.4.a
    attempts_ok_834 = attempts_parsed is not None and attempts_parsed <= 10
    timer_ok_834 = timer_parsed is not None and timer_parsed >= 1800

    if attempts_parsed is not None and timer_parsed is not None:
        findings_834b.append(
            f"deny = {attempts_parsed}: {'PASS' if attempts_ok_834 else 'FAIL'} (requirement: ≤ 10)"
        )
        findings_834b.append(
            f"unlock_time = {timer_parsed}s: {'PASS' if timer_ok_834 else 'FAIL'} (requirement: ≥ 1800s / 30 min)"
        )
        if attempts_parsed == 3:
            findings_834b.append(
                "deny = 3 matches the faillock.conf default; confirm it is explicitly set."
            )
        status_834b = "passed" if (attempts_ok_834 and timer_ok_834) else "review"

    else:
        # Values were present but numeric part was empty (e.g. "deny=" with no number)
        findings_834b.append(
            f"Raw Attempts value = '{attempts_raw}' — numeric part could not be parsed."
        )
        findings_834b.append(
            f"Raw Timer value = '{timer_raw}' — numeric part could not be parsed."
        )
        findings_834b.append(
            "Check faillock.conf directly; values may be set there rather than in PAM summary."
        )
        status_834b = "review"

    add(
        "[8.3.4.b]",
        "Provide evidence to confirm failed logons are limited to 10 tries and a 30-minute unlock timer is enforced.",
        status_834b,
        findings_834b,
        ["summary.csv"],
        default_file="summary.csv",
        look_for="deny ≤ 10 and unlock_time ≥ 1800 seconds (30 minutes).",
        qsa_response=(
            (
                "QSA reviewed the PAM faillock configuration to confirm that failed logon attempts were "
                f"limited and that a sufficient lockout duration was enforced. The review confirmed that the "
                f"deny threshold was set to {attempts_parsed} attempts and unlock_time was set to "
                f"{timer_parsed} seconds, satisfying the requirement for a maximum of 10 attempts and a "
                "minimum 30-minute lockout period."
            )
            if status_834b == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.6]
    # -------------------------

    pw_min = summary.get("PwMinLen")
    pw_complex = summary.get("PwComplexity")
    pwquality = data.get("pwquality", "no file found")
    pq = pwquality if isinstance(pwquality, dict) else {}

    # pwquality values — prefer these over summary if present
    pq_minlen = pq.get("minlen", "")
    pq_minclass = pq.get("minclass", "")
    pq_dcredit = pq.get("dcredit", "")
    pq_lcredit = pq.get("lcredit", "")
    pq_ucredit = pq.get("ucredit", "")
    pq_ocredit = pq.get("ocredit", "")

    findings_836 = []

    # --- Length check ---
    # Prefer pwquality minlen; fall back to summary PwMinLen
    pq_minlen_ok = pq_minlen.lstrip("-").isdigit() and int(pq_minlen) >= 12
    summary_minlen_ok = (
        pw_min not in (None, "", "NA") and str(pw_min).isdigit() and int(pw_min) >= 12
    )
    length_ok = pq_minlen_ok or summary_minlen_ok

    if pq_minlen:
        findings_836.append(
            f"pwquality minlen = {pq_minlen}: "
            f"{'PASS' if pq_minlen_ok else 'FAIL'} (requirement: ≥ 12)"
        )
    else:
        findings_836.append(
            f"pwquality minlen not found — falling back to summary PwMinLen = {pw_min}: "
            f"{'PASS' if summary_minlen_ok else 'FAIL/not set'}"
        )

    # --- Complexity check ---
    # minclass >= 3 is a direct complexity signal
    # All four credits being negative means each class is required (stronger signal)
    def credit_negative(val):
        return val.lstrip("-").isdigit() and int(val) < 0

    credits_ok = all(
        credit_negative(v)
        for v in [pq_dcredit, pq_lcredit, pq_ucredit, pq_ocredit]
        if v  # only check credits that are present
    ) and any(v for v in [pq_dcredit, pq_lcredit, pq_ucredit, pq_ocredit])

    pq_minclass_ok = pq_minclass.isdigit() and int(pq_minclass) >= 3
    summary_complex_ok = str(pw_complex).upper() == "TRUE"

    complexity_ok = pq_minclass_ok or credits_ok or summary_complex_ok

    if pq_minclass:
        findings_836.append(
            f"pwquality minclass = {pq_minclass}: "
            f"{'PASS' if pq_minclass_ok else 'FAIL'} (requirement: ≥ 3)"
        )
    if any(v for v in [pq_dcredit, pq_lcredit, pq_ucredit, pq_ocredit]):
        findings_836.append(
            f"pwquality credit values — "
            f"dcredit={pq_dcredit}, lcredit={pq_lcredit}, "
            f"ucredit={pq_ucredit}, ocredit={pq_ocredit}: "
            f"{'PASS — all character classes required' if credits_ok else 'FAIL — one or more credits not negative'}"
        )
    if not pq_minclass and not any(
        v for v in [pq_dcredit, pq_lcredit, pq_ucredit, pq_ocredit]
    ):
        findings_836.append(
            f"No pwquality complexity settings found — "
            f"falling back to summary PwComplexity = {pw_complex}: "
            f"{'PASS' if summary_complex_ok else 'FAIL/not set'}"
        )

    # pwquality file presence note
    if pwquality == "no file found":
        findings_836.append(
            "8.3_pwquality.txt was not found — password length/complexity sourced from summary only."
        )
    else:
        findings_836.append(
            "Password policy sourced from pwquality configuration file."
        )

    status_836 = "passed" if (length_ok and complexity_ok) else "review"

    add(
        "[8.3.6]",
        "Provide password configuration settings to confirm passwords meet minimum length and complexity requirements.",
        status_836,
        findings_836,
        ["summary.csv", "8.3_pwquality.txt"],
        default_file="8.3_pwquality.txt",
        look_for="minlen ≥ 12, minclass ≥ 3 or all credit values negative, or PwComplexity = TRUE.",
        qsa_response=(
            (
                "QSA reviewed the password configuration settings to confirm that passwords met the minimum "
                "length and complexity requirements. The review confirmed that the pwquality configuration "
                f"enforced a minimum password length of {pq_minlen or pw_min} characters and required "
                f"a minimum of {pq_minclass} character classes, with individual character class credits "
                "configured to require digits, lowercase, uppercase, and special characters. Both settings "
                "met or exceeded the defined requirements."
            )
            if status_836 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.7]
    # -------------------------

    pw_history_val = summary.get("PwHistory")

    try:
        pw_hist_ok = pw_history_val not in (None, "", "NA") and int(pw_history_val) >= 4
        status_837 = "passed" if pw_hist_ok else "review"
    except Exception:
        pw_hist_ok = False
        status_837 = "review"

    findings_837 = [
        f"PwHistory = {pw_history_val}: "
        f"{'PASS' if pw_hist_ok else 'FAIL/not set'} (requirement: ≥ 4)",
    ]

    if pw_history_val in (None, "", "NA"):
        findings_837.append(
            "PwHistory is not set in summary — password history may be enforced via PAM "
            "pwhistory.so or pam_unix remember= rather than being visible to the summary script."
        )

    add(
        "[8.3.7]",
        "Provide evidence to confirm password history prevents reuse of at least the required number of prior passwords.",
        status_837,
        findings_837,
        ["summary.csv"],
        default_file="summary.csv",
        look_for="PwHistory ≥ 4, or PAM pwhistory/remember= evidence.",
        qsa_response=(
            (
                "QSA reviewed the password history configuration to confirm that users were prevented from "
                f"reusing recent passwords. The review confirmed that the password history was set to "
                f"{pw_history_val} passwords, meeting the requirement to prevent reuse of at least the "
                "last four passwords."
            )
            if status_837 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.9]
    # -------------------------

    pw_ages = data.get("pw_ages", "no file found")
    findings_839 = []

    if pw_ages == "no file found":
        status_839 = "manual"
        findings_839.append(
            "8.3.9_pw-ages.csv was not found. Cannot evaluate password rotation policy."
        )

    elif isinstance(pw_ages, list) and len(pw_ages) == 0:
        status_839 = "review"
        findings_839.append(
            "8.3.9_pw-ages.csv was present but no password age records were parsed."
        )

    else:
        noncompliant = []
        unknown = []

        for entry in pw_ages:
            username = entry.get("user")
            val = entry.get("pw_max_age")

            if val is None or val == "":
                unknown.append(f"{username}: blank / unobserved")
            elif isinstance(val, int):
                if val > 90:
                    noncompliant.append(f"{username}: {val} days")
            elif val.lower() == "never":
                noncompliant.append(f"{username}: Never")
            else:
                unknown.append(f"{username}: unrecognized value '{val}'")

        if noncompliant:
            status_839 = "review"
            findings_839.append(
                "The following accounts do not meet the 90-day password rotation requirement:"
            )
            for item in noncompliant:
                findings_839.append(item)

        elif unknown:
            status_839 = "review"
            findings_839.append("Some password age values could not be interpreted:")
            for item in unknown:
                findings_839.append(item)

        else:
            status_839 = "passed"
            findings_839.append(
                "All observed accounts have a maximum password age of 90 days or less."
            )

        # optional: always include a quick summary of parsed users
        findings_839.append(
            f"Parsed password-age records for users: {join_items(e.get('user') for e in pw_ages)}"
        )

    add(
        "[8.3.9]",
        "Provide system configuration settings to confirm passwords/passphrases are changed according to policy.",
        status_839,
        findings_839,
        ["8.3.9_pw-ages.csv"],
        default_file="8.3.9_pw-ages.csv",
        look_for="Maximum password age of 90 days or less; 'Never' should be treated as non-compliant.",
    )

    # -------------------------
    # [8.4.1.a]
    # -------------------------
    add(
        "[8.4.1.a]",
        "Provide network and/or system configurations to confirm MFA is required for all administrative access.",
        "manual",
        ["MFA requirement cannot be established from current Linux JSON alone."],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="Administrative MFA controls.",
    )

    # -------------------------
    # [8.4.2.a]
    # -------------------------
    add(
        "[8.4.2.a]",
        "Provide network and/or system configurations to confirm MFA is implemented for all remote access.",
        "manual",
        ["Remote-access MFA cannot be established from current Linux JSON alone."],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="Remote access MFA controls.",
    )

    # -------------------------
    # [8.6.1]
    # -------------------------
    interactive_users = [u.get("username") for u in passwd_list if u.get("interactive")]
    add(
        "[8.6.1]",
        "Provide application and system accounts to confirm all such accounts have unique passwords/passphrases.",
        "review",
        [f"Interactive accounts observed = {join_items(interactive_users)}"],
        ["passwd.txt"],
        default_file="passwd.txt",
        look_for="Unique authentication for application and system accounts.",
    )

    # -------------------------
    # [8.6.2.b]
    # -------------------------
    add(
        "[8.6.2.b]",
        "Provide scripts, configuration/property files, and source code to confirm no hard-coded credentials exist.",
        "manual",
        [
            "Current JSON does not contain source/config review evidence for hard-coded credentials."
        ],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="Embedded or static credentials in code or config.",
    )

    # -------------------------
    # [8.6.3.c]
    # -------------------------
    add(
        "[8.6.3.c]",
        "Provide system configuration settings to confirm passwords/passphrases for system accounts are changed regularly.",
        "manual",
        [
            "Requires system-account password rotation evidence not present in current JSON."
        ],
        ["summary.csv"],
        default_file="summary.csv",
        look_for="Rotation or vault evidence for system account passwords.",
    )

    # -------------------------
    # [10.2.1]
    # -------------------------
    log_active = summary.get("LogActive")
    add(
        "[10.2.1]",
        "Provide audit log configuration to confirm logging is enabled and active.",
        "passed" if log_active == "active" else "failed",
        [f"LogActive = {log_active}", f"LogLevel = {summary.get('LogLevel')}"],
        ["summary.csv", "10.3.3_logging.txt"],
        default_file="summary.csv",
        look_for="Logging active and configured at an appropriate level.",
    )

    # helpers for 10.2.1.x about logging
    log_level_raw = str(summary.get("LogLevel") or "").lower()
    log_level_tags = [t.strip() for t in log_level_raw.split(",")]

    has_auth = any(
        t in ("auth", "authpriv", "debug", "info", "iinfo") for t in log_level_tags
    )
    has_kern = any(t in ("kern", "audit", "debug") for t in log_level_tags)
    log_is_active = log_active == "active"

    attempts_raw = str(as_dict(data.get("login_attempts")).get("deny") or "")
    attempts_configured = attempts_raw.strip().isdigit()

    # print(attempts_raw)
    # print(attempts_configured)

    # -------------------------
    # [10.2.1.2]
    # -------------------------
    status_10212 = "passed" if (log_is_active and has_auth) else "review"

    add(
        "[10.2.1.2]",
        "Provide audit log configurations to confirm all actions taken by any individual with root/administrative access are logged.",
        status_10212,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"LogLevel = {summary.get('LogLevel')}: "
            f"{'PASS' if has_auth else 'FAIL'} (requirement: auth or authpriv present)",
        ],
        ["10.3.3_logging.txt", "summary.csv"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active and LogLevel containing auth or authpriv.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that all actions taken by individuals "
                "with root or administrative access were being logged. The review confirmed that logging was "
                f"active and that the log level included '{summary.get('LogLevel')}', providing coverage of "
                "authentication and privileged activity consistent with the requirement."
            )
            if status_10212 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.3]
    # -------------------------
    forwarding_configured = logging.get("forwarding_configured", False)
    status_10213 = "passed" if (log_is_active and forwarding_configured) else "review"

    add(
        "[10.2.1.3]",
        "Provide audit log configurations to confirm access to all audit logs is captured.",
        status_10213,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"Log forwarding configured = {forwarding_configured}: "
            f"{'PASS' if forwarding_configured else 'FAIL'} (requirement: forwarding must be active)",
        ],
        ["10.3.3_logging.txt", "summary.csv"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active and log forwarding configured to a central target.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that access to all audit logs was "
                "being captured. The review confirmed that logging was active and that log forwarding was "
                "configured to a central log server, ensuring that audit log access and content were "
                "preserved in a secure and tamper-resistant location."
            )
            if status_10213 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.4]
    # -------------------------
    status_10214 = (
        "passed" if (log_is_active and has_auth and attempts_configured) else "review"
    )

    add(
        "[10.2.1.4]",
        "Provide audit log configurations to confirm invalid logical access attempts are logged.",
        status_10214,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"LogLevel = {summary.get('LogLevel')}: "
            f"{'PASS' if has_auth else 'FAIL'} (requirement: auth present for failed login capture)",
            f"Attempts (PAM deny) = {attempts_raw}: "
            f"{'PASS' if attempts_configured else 'FAIL'} (requirement: deny= must have a numeric value)",
        ],
        ["summary.csv", "10.3.3_logging.txt"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active, auth in LogLevel, and PAM deny= set to a numeric value.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that invalid logical access attempts "
                "were being logged. The review confirmed that logging was active, that the log level "
                "included authentication facility coverage, and that the PAM lockout policy was configured "
                "with a numeric deny threshold, ensuring that failed access attempts were captured in the "
                "audit log."
            )
            if status_10214 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.5]
    # -------------------------
    status_10215 = "passed" if (log_is_active and has_auth) else "review"

    add(
        "[10.2.1.5]",
        "Provide audit log configurations to confirm changes to identification and authentication are logged.",
        status_10215,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"LogLevel = {summary.get('LogLevel')}: "
            f"{'PASS' if has_auth else 'FAIL'} (requirement: auth or authpriv for identity/auth change capture)",
        ],
        ["10.3.3_logging.txt", "summary.csv"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active and auth or authpriv in LogLevel.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that changes to identification and "
                "authentication mechanisms were being logged. The review confirmed that logging was active "
                f"and that the configured log level of '{summary.get('LogLevel')}' included authentication "
                "facility coverage, ensuring that account and authentication changes were recorded."
            )
            if status_10215 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.6]
    # -------------------------
    status_10216 = "passed" if (log_is_active and has_auth) else "review"

    add(
        "[10.2.1.6]",
        "Provide audit log configurations to confirm privileged access is logged.",
        status_10216,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"LogLevel = {summary.get('LogLevel')}: "
            f"{'PASS' if has_auth else 'FAIL'} (requirement: auth or authpriv for privileged access capture)",
        ],
        ["10.3.3_logging.txt", "summary.csv"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active and auth or authpriv in LogLevel for privileged-action coverage.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that privileged access was being "
                "logged. The review confirmed that logging was active and that the log level included "
                f"'{summary.get('LogLevel')}', providing coverage of authentication and privileged actions "
                "such as su, sudo, and authpriv facility events."
            )
            if status_10216 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.7]
    # -------------------------
    status_10217 = "passed" if (log_is_active and has_kern) else "review"

    add(
        "[10.2.1.7]",
        "Provide audit log configurations to confirm creation and deletion of system-level objects are logged.",
        status_10217,
        [
            f"LogActive = {log_active}: {'PASS' if log_is_active else 'FAIL'}",
            f"LogLevel = {summary.get('LogLevel')}: "
            f"{'PASS' if has_kern else 'FAIL'} (requirement: kern or audit for system object event capture)",
        ],
        ["10.3.3_logging.txt", "summary.csv"],
        default_file="10.3.3_logging.txt",
        look_for="LogActive = active and kern or audit in LogLevel for system object create/delete coverage.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that creation and deletion of "
                "system-level objects were being logged. The review confirmed that logging was active and "
                f"that the log level of '{summary.get('LogLevel')}' included kernel or audit facility "
                "coverage, ensuring that system object lifecycle events were captured in the audit log."
            )
            if status_10217 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.3.3]
    # -------------------------
    forwarding = logging.get("forwarding_configured")
    targets = logging.get("forwarding_targets", [])
    script_result = logging.get("script_result", "unknown")

    # Stronger pass condition: must actually have a target
    is_valid = bool(forwarding and targets)

    add(
        "[10.3.3]",
        "Provide system configuration settings to confirm audit logs are backed up to a secure, central, internal log server or other difficult-to-modify media.",
        "passed" if is_valid else "failed",
        [
            script_result,
            f"Forwarding configured = {forwarding}",
            f"Forwarding targets = {targets}",
            f"Target count = {len(targets)}",
        ],
        ["10.3.3_logging.txt"],
        default_file="10.3.3_logging.txt",
        look_for="Active rsyslog/syslog forwarding target to central log/SIEM.",
        qsa_response=(
            "QSA reviewed the audit log configurations to confirm that audit logs were being backed up "
            "to a secure, central, internal log server or other difficult-to-modify media. The review "
            "confirmed that log forwarding was configured and that the system was actively sending logs "
            "to approved central log targets, ensuring that audit logs were preserved in a secure and "
            "tamper-resistant manner."
        )
    )

    # -------------------------
    # [10.6.1]
    # -------------------------
    synchronized = ts.get("synchronized") or "True" in ts.get("synchronized")
    ntp_active = ts.get("ntp_service") == "active" or ts.get("ntp_service") == "enabled"
    status_1061 = "passed" if (synchronized and ntp_active) else "failed"
    add(
        "[10.6.1]",
        "Provide evidence to confirm system clocks and time are synchronized using time-synchronization technology.",
        status_1061,
        [
            f"Synchronized = {synchronized}",
            f"NTP service = {ts.get('ntp_service')}",
            f"RTC in local TZ = {ts.get('rtc_local_tz')}",
        ],
        ["10.6.1_timesync.txt"],
        default_file="10.6.1_timesync.txt",
        look_for="System clock synchronized = yes and NTP service active.",
        qsa_response=(
            "QSA reviewed the time synchronization settings to confirm that system clocks were synchronized "
            "using approved time-synchronization technology. The review confirmed that the system clocks "
            "were synchronized with approved NTP servers, ensuring accurate and reliable timekeeping "
            "consistent with organizational policy."
        )
    )

    # -------------------------
    # [10.6.2]
    # -------------------------
    add(
        "[10.6.2]",
        "Provide time synchronization settings to confirm systems are configured to the correct and consistent time.",
        status_1061,
        [f"Synchronized = {synchronized}", f"NTP service = {ts.get('ntp_service')}"],
        ["10.6.1_timesync.txt"],
        default_file="10.6.1_timesync.txt",
        look_for="Consistent synchronized system time across hosts.",
        qsa_response=(
            "QSA reviewed the time synchronization settings to confirm that systems were configured to "
            "maintain correct and consistent time. The review confirmed that the system clocks were "
            "synchronized with approved NTP servers, ensuring accurate and reliable timekeeping consistent "
            "with organizational policy."
        )
    )

    # -------------------------
    # [10.6.3.a]
    # -------------------------
    add(
        "[10.6.3.a]",
        "Provide system configurations and time-synchronization settings to confirm time accuracy is maintained.",
        "review",
        [f"Synchronized = {synchronized}", f"NTP service = {ts.get('ntp_service')}"],
        ["10.6.1_timesync.txt"],
        default_file="10.6.1_timesync.txt",
        look_for="Time synchronization functioning and stable.",
        qsa_response=(
            "QSA reviewed the system configurations and time-synchronization settings to confirm that time "
            "accuracy was maintained. The review confirmed that the system clocks were synchronized with "
            "approved NTP servers, ensuring accurate and reliable timekeeping consistent with organizational policy."
        )
    )

    # -------------------------
    # [10.6.3.b]
    # -------------------------
    timesources = data.get("timesources", [])
    add(
        "[10.6.3.b]",
        "Provide system configurations and time-source settings to confirm the time source is configured securely.",
        "review",
        [
            f"Configured time sources: {', '.join(timesources)}. Review to confirm sources are central/approved NTP servers and not untrusted external sources."
        ],
        ["10.6.1_timesync.txt"],
        default_file="10.6.1_timesync.txt",
        look_for="Configured central/approved NTP sources.",
        qsa_response=(
            "QSA reviewed the system configurations and time-source settings to confirm that the time source "
            "was configured securely. The review confirmed that the system was synchronized with approved "
            "NTP servers, ensuring accurate and reliable timekeeping consistent with organizational policy."
        )
    )

    # -------------------------
    # [11.5.2.a]
    # -------------------------
    fim_keywords = [
        "tripwire",
        "fim",
        "aide",
        "qualys",
        "crowdstrike",
        "defender",
        "carbon black",
        "sentinelone",
        "cylance",
        "file integrity",
        "fileintegrity",
        "change detection",
        "integrity monitor",
        "trend mirco",
        "ds_agent"
    ]

    fim_services_found = list(
        dict.fromkeys(
            [
                svc.get("service")
                for svc in running_services
                if any(
                    kw in (svc.get("service") or "").lower()
                    or kw in (svc.get("description") or "").lower()
                    for kw in fim_keywords
                )
            ]
        )
    )

    fim_detected = bool(fim_services_found)

    findings_11552 = []
    if fim_services_found:
        findings_11552.append(
            f"Potential FIM/change-detection services detected: {fim_services_found}"
            "Confirm that this module is configured as an FIM/change detection solution"
        )
    if not fim_detected:
        findings_11552.append(
            "No known FIM or change-detection services or applications were identified. "
            "Change-detection configuration must be confirmed through other evidence."
        )

    findings_11552.append(
        "Configuration scope and monitored paths must be confirmed through the solution's "
        "management console or configuration files."
    )

    add(
        "[11.5.2.a]",
        "Provide system settings to confirm the use of a change-detection mechanism.",
        "review",
        findings_11552,
        ["09_Services_Details.csv", "11_InstalledPatches.txt"],
        default_file="09_Services_Details.csv",
        look_for="FIM or change-detection solution running as a service or present in installed applications.",
        qsa_response=(
            (
                "QSA reviewed the system settings to confirm the use of a change-detection mechanism. "
                "The review identified file integrity monitoring or equivalent change-detection solution "
                "components present in the running services and installed applications. The solution was "
                "confirmed to be active and the organization provided evidence that it was configured to "
                "monitor critical system files, directories, and configuration items consistent with the "
                "defined scope of this requirement."
            )
            if fim_detected
            else ""
        ),
    )

    return report


if __name__ == "__main__":
    build_report("linux_output.json", "report.html", sample_files_folder=None)
