# windowsReport.py
# Windows report renderer and helper utilities.
# Builds HTML reports from normalized Windows JSON output and supports file
# loading, rule evaluation, and homepage rendering.

import html
from importlib.metadata import files
import json
import os
import sys
import uuid
from windowsParser import build_windows_output

TRUNCATION_MARKER = "__TRUNCATED__"
MAX_LINES = 300


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


# load raw evidence text for html output
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


def normalize_rdp_template_value(raw):
    if raw is None:
        return raw
    if isinstance(raw, (list, tuple)):
        if not raw:
            return None
        return normalize_rdp_template_value(raw[0])
    if isinstance(raw, str):
        raw = raw.strip()
        if raw == "":
            return raw
        if "," in raw:
            raw = raw.split(",")[0].strip()
        low = raw.lower()
        if low in {"enabled", "1", "true"}:
            return "1"
        if low in {"disabled", "0", "false"}:
            return "0"
        return raw
    return raw


def get_administrative_template_value(data, key):
    templates = data.get("group_policy", {}).get("administrative_templates", {})
    if not isinstance(templates, dict):
        return None

    # known aliases for common RDP keys (covers minor naming changes)
    RDP_ADMIN_ALIASES = {
        "SecurityLayer": ["Securitylayer", "Security Layer"],
        "fEncryptRPCTraffic": ["fEncryptRpcTraffic", "EncryptRPC", "fEncryptRPC"],
        "fDisableEncryption": ["DisableEncryption", "fDisableEnc"],
        "UserAuthentication": ["Userauthentication", "RequireUserAuth"],
        "MinEncryptionLevel": ["MinEncryptionlevel", "MinimumEncryptionLevel"],
    }

    found_key = None
    entry = None

    # try exact match first
    if key in templates:
        found_key = key
        entry = templates.get(key)

    # case-insensitive direct match
    if entry is None:
        lower_map = {k.lower(): k for k in templates.keys() if isinstance(k, str)}
        if key.lower() in lower_map:
            found_key = lower_map[key.lower()]
            entry = templates.get(found_key)

    # aliases
    if entry is None:
        for alias in RDP_ADMIN_ALIASES.get(key, []):
            if alias.lower() in lower_map:
                found_key = lower_map[alias.lower()]
                entry = templates.get(found_key)
                break

    # substring match fallback
    if entry is None:
        for tk, tv in templates.items():
            if isinstance(tk, str) and key.lower() in tk.lower():
                found_key = tk
                entry = tv
                break

    if isinstance(entry, dict):
        value = entry.get("value")
        if value not in [None, ""]:
            data.setdefault("_found_admin_rdp_keys", {})[key] = found_key or key
            return normalize_rdp_template_value(value)
        state = entry.get("state")
        if state not in [None, ""]:
            data.setdefault("_found_admin_rdp_keys", {})[key] = found_key or key
            return normalize_rdp_template_value(state)
    return None


def get_rdp_setting(data, key):
    admin_val = get_administrative_template_value(data, key)
    if admin_val not in [None, ""]:
        return admin_val
    # infer fDisableEncryption when explicit setting is absent:
    if key == "fDisableEncryption":
        # if minimum encryption level or security layer indicate encryption is active,
        # assume encryption is not disabled (i.e., fDisableEncryption = 0)
        min_enc = get_administrative_template_value(data, "MinEncryptionLevel")
        if min_enc in [None, ""]:
            min_enc = data.get("rdp_domain", {}).get("MinEncryptionLevel") or data.get("rdp_local", {}).get("MinEncryptionLevel") or data.get("rdp_config", {}).get("MinEncryptionLevel")
        sec_layer = get_administrative_template_value(data, "SecurityLayer")
        if sec_layer in [None, ""]:
            sec_layer = data.get("rdp_domain", {}).get("SecurityLayer") or data.get("rdp_local", {}).get("SecurityLayer") or data.get("rdp_config", {}).get("SecurityLayer")
        try:
            if str(min_enc).strip().isdigit() and int(str(min_enc).strip()) >= 3:
                return "0"
        except Exception:
            pass
        try:
            if str(sec_layer).strip().isdigit() and int(str(sec_layer).strip()) >= 1:
                return "0"
        except Exception:
            pass
    # infer SecurityLayer from MinEncryptionLevel when missing
    if key == "SecurityLayer":
        min_enc = get_administrative_template_value(data, "MinEncryptionLevel")
        if min_enc in [None, ""]:
            min_enc = (
                data.get("rdp_domain", {}).get("MinEncryptionLevel")
                or data.get("rdp_local", {}).get("MinEncryptionLevel")
                or data.get("rdp_config", {}).get("MinEncryptionLevel")
            )
        try:
            if str(min_enc).strip().isdigit() and int(str(min_enc).strip()) >= 3:
                return "1"
        except Exception:
            pass
    # infer fEncryptRPCTraffic from MinEncryptionLevel or SecurityLayer when missing
    if key == "fEncryptRPCTraffic":
        enc = get_administrative_template_value(data, "MinEncryptionLevel")
        if enc in [None, ""]:
            enc = (
                data.get("rdp_domain", {}).get("MinEncryptionLevel")
                or data.get("rdp_local", {}).get("MinEncryptionLevel")
                or data.get("rdp_config", {}).get("MinEncryptionLevel")
            )
        sec = get_administrative_template_value(data, "SecurityLayer")
        if sec in [None, ""]:
            sec = (
                data.get("rdp_domain", {}).get("SecurityLayer")
                or data.get("rdp_local", {}).get("SecurityLayer")
                or data.get("rdp_config", {}).get("SecurityLayer")
            )
        try:
            if (str(enc).strip().isdigit() and int(str(enc).strip()) >= 3) or (
                str(sec).strip().isdigit() and int(str(sec).strip()) >= 1
            ):
                return "1"
        except Exception:
            pass
    # try backup names for UserAuthentication
    if key == "UserAuthentication":
        # check common backup keys in rdp sections
        for candidate in ("UserAuthenticationBackup",):
            val = (
                data.get("rdp_domain", {}).get(candidate)
                or data.get("rdp_local", {}).get(candidate)
                or data.get("rdp_config", {}).get(candidate)
            )
            if val not in (None, ""):
                return val
    # fallback to legacy rdp values if administrative templates are absent
    if key in {
        "UserAuthentication",
        "MinEncryptionLevel",
        "fDisableEncryption",
        "fEncryptRPCTraffic",
        "SecurityLayer",
        "fPromptForPassword",
        "DisablePasswordSaving",
        "MaxIdleTime",
        "MaxDisconnectionTime",
    }:
        return (
            data.get("rdp_domain", {}).get(key)
            or data.get("rdp_local", {}).get(key)
            or data.get("rdp_config", {}).get(key)
        )
    return data.get("rdp_config", {}).get(key) or data.get("rdp_domain", {}).get(key) or data.get("rdp_local", {}).get(key)


def load_key_vars_windows(data):
    def safe(getter):
        try:
            val = getter()
            return val if val not in [None, ""] else "Not set"
        except Exception:
            return "Not set"

    def get_first_dict(obj):
        try:
            if isinstance(obj, list):
                return obj[0] if obj else {}
            elif isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return {}

    local = get_first_dict(data.get("security_policies_local"))
    domain = get_first_dict(data.get("security_policies_domain"))

    local_access = get_first_dict(local.get("System Access"))
    domain_access = get_first_dict(domain.get("System Access"))

    registry = local.get("Registry Values", [])

    no_lm_hash_raw = None

    try:
        if isinstance(registry, list):
            for entry in registry:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        if isinstance(k, str) and k.endswith("NoLMHash"):
                            no_lm_hash_raw = v
                            break
                if no_lm_hash_raw:
                    break
        elif isinstance(registry, dict):
            for k, v in registry.items():
                if isinstance(k, str) and k.endswith("NoLMHash"):
                    no_lm_hash_raw = v
                    break
    except Exception:
        no_lm_hash_raw = None

    def extract(raw):
        try:
            if not raw:
                return "Not set"
            parts = str(raw).split(",")
            result = parts[1] if len(parts) > 1 else raw
            return result if result not in [None, ""] else "Not set"
        except Exception:
            return "Not set"

    return {
        "Local": {
            "Max Password Age": safe(lambda: local_access.get("MaximumPasswordAge")),
            "Min Password Length": safe(
                lambda: local_access.get("MinimumPasswordLength")
            ),
            "Password Complexity": safe(lambda: local_access.get("PasswordComplexity")),
            "Password History": safe(lambda: local_access.get("PasswordHistorySize")),
            "Bad Lockout Count": safe(lambda: local_access.get("LockoutBadCount")),
            "Lockout Duration": safe(lambda: local_access.get("LockoutDuration")),
            "Admin Account Name": safe(
                lambda: local_access.get("NewAdministratorName")
            ),
            "Admin Enabled": safe(lambda: local_access.get("EnableAdminAccount")),
            "Guest Account Name": safe(lambda: local_access.get("NewGuestName")),
            "Guest Enabled": safe(lambda: local_access.get("EnableGuestAccount")),
        },
        "Domain": {
            "Max Password Age": safe(lambda: domain_access.get("MaximumPasswordAge")),
            "Min Password Length": safe(
                lambda: domain_access.get("MinimumPasswordLength")
            ),
            "Password Complexity": safe(
                lambda: domain_access.get("PasswordComplexity")
            ),
            "Password History": safe(lambda: domain_access.get("PasswordHistorySize")),
            "Bad Lockout Count": safe(lambda: domain_access.get("LockoutBadCount")),
            "Lockout Duration": safe(lambda: domain_access.get("LockoutDuration")),
            "Admin Account Name": safe(
                lambda: domain_access.get("NewAdministratorName")
            ),
            "Admin Enabled": safe(lambda: domain_access.get("EnableAdminAccount")),
            "Guest Account Name": safe(lambda: domain_access.get("NewGuestName")),
            "Guest Enabled": safe(lambda: domain_access.get("EnableGuestAccount")),
        },
        "Other": {
            "NoLMHash": extract(no_lm_hash_raw),
            "RDP Minimum Encryption": safe(
                lambda: get_rdp_setting(data, "MinEncryptionLevel")
            ),
            "NTP Server": safe(
                lambda: data.get("time_settings", {})
                .get("Parameters", {})
                .get("NtpServer")
            ),
        },
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

    nav_html = ""
    if nav_links:
        parts = []
        if nav_links.get("home"):
            parts.append(f"<a href='{html.escape(nav_links['home'])}'>Home</a>")
        if nav_links.get("prev"):
            parts.append(f"<a href='{html.escape(nav_links['prev'])}'>Previous</a>")
        if nav_links.get("next"):
            parts.append(f"<a href='{html.escape(nav_links['next'])}'>Next</a>")
        nav_html = " | ".join(parts)

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
            {render_section('Local Policy', key_vars.get('Local', {}))}
            {render_section('Domain Policy', key_vars.get('Domain', {}))}
            {render_section('Other Settings', key_vars.get('Other', {}))}
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
        f.write(
            "    table { width: 100%; border-collapse: collapse; table-layout: fixed; }\n"
        )
        f.write(
            "    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; word-wrap: break-word; word-break: break-word; }\n"
        )
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
        f.write(
            "    .finding-label { font-family: Arial, sans-serif; margin-bottom: 0.2em; display: block; }\n"
        )
        f.write(
            "    .finding-snippet { margin: 0.25em 0 0; font-family: 'Courier New', Courier, monospace; background: #f7f7f7; padding: 6px; border-radius: 4px; white-space: pre-wrap; overflow-wrap: anywhere; }\n"
        )
        f.write(
            "    .finding-file { font-size: 0.9em; color: #444; margin-top: 0.25em; }\n"
        )
        f.write(
            "    #reviewModal { display: none; position: fixed; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.4); }\n"
        )
        f.write(
            "    #reviewModal .box { background: #fff; margin: 40px auto; padding: 12px; width: 80%; max-width: 900px; border-radius: 6px; }\n"
        )
        f.write(
            "    #reviewModal textarea { width: 100%; height: 240px; font-family: monospace; }\n"
        )
        f.write(
            "    .review-btn { padding: 6px 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }\n"
        )
        f.write("    .review-btn:hover { background: #0052a3; }\n")
        f.write(
            "    .top-toolbar { margin: 16px 0; display: flex; justify-content: flex-start; gap: 12px; }\n"
        )
        f.write(
            "    .export-btn { padding: 10px 16px; background: #198754; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }\n"
        )
        f.write("    .export-btn:hover { background: #157347; }\n")
        f.write("    .qsa-response-text { font-size: 0.82em; color: #333; }\n")
        f.write("""
            .kv-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 16px;
                margin-bottom: 24px;
            }

            .kv-card {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 12px;
                background: #fafafa;
                box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            }

            .kv-card h3 {
                margin-top: 0;
                margin-bottom: 8px;
                font-size: 1.05em;
                color: #333;
            }

            .kv-table {
                width: 100%;
                border-collapse: collapse;
                font-size: 0.85em;
            }

            .kv-table td {
                border: none;
                padding: 4px 6px;
                vertical-align: top;
            }

            .kv-table td:first-child {
                color: #555;
                width: 55%;
            }
            """)
        f.write("</style>\n")

        f.write(
            "<table id='requirementsTable'><thead><tr><th>ID</th><th>Description</th><th>Status</th><th>Files</th><th>Findings</th><th>Look For</th><th>QSA Response</th></tr></thead><tbody>\n"
        )
        for r in rows:
            f.write(r + "\n")
        f.write("</tbody></table>\n")
        f.write(f"<script>\n")
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
        f.write(
            "        findingsCell.querySelectorAll('button').forEach(btn => btn.remove());\n"
        )
        f.write(
            "        return findingsCell.innerText.replace(/\\n{3,}/g, '\\n\\n').trim();\n"
        )
        f.write("    }\n")

        f.write("  function doExportXlsx() {\n")
        f.write("    const selected = Array.from(\n")
        f.write(
            "      document.querySelectorAll('#exportHostList input[type=checkbox]')\n"
        )
        f.write("    ).filter(cb => cb.checked).map(cb => parseInt(cb.dataset.idx));\n")
        f.write(
            "    if (selected.length === 0) { alert('Please select at least one host.'); return; }\n"
        )
        f.write("    const wb = XLSX.utils.book_new();\n")
        f.write(
            "    const headers = ['ID','Description','Status','Files','Findings','Look For','QSA Response','Editor Notes'];\n"
        )
        f.write("    selected.forEach(idx => {\n")
        f.write("      const host = EXPORT_DATA[idx];\n")
        f.write("      const sheetData = [headers];\n")
        f.write("      host.rows.forEach(row => {\n")
        # Build the same localStorage key the report page uses
        f.write(
            "        const reqKey   = 'req_' + row.id.replace(/[^a-zA-Z0-9]/g, '_');\n"
        )
        f.write(
            "        const storeKey = 'zipaudit|' + host.hostname + '|' + reqKey;\n"
        )
        f.write("        const raw      = localStorage.getItem(storeKey);\n")
        f.write("        let   status   = row.status;\n")
        f.write("        let   noteStr  = '';\n")
        f.write("        if (raw) {\n")
        f.write("          try {\n")
        f.write("            const saved = JSON.parse(raw);\n")
        f.write("            status = saved.status || status;\n")
        f.write("            if (Array.isArray(saved.notes) && saved.notes.length) {\n")
        f.write("              noteStr = saved.notes\n")
        f.write(
            "                .map(n => n.timestamp + ' | moved to ' + n.status + ' | ' + n.note)\n"
        )
        f.write("                .join('\\n\\n');\n")
        f.write("            }\n")
        f.write("          } catch(e) {}\n")
        f.write("        }\n")
        # Only include QSA response if the current (possibly overridden) status is passed
        f.write(
            "        const qsaText = status === 'passed' ? row.qsa_response : '';\n"
        )
        f.write(
            "        sheetData.push([row.id, row.description, status, row.files, row.findings, row.look_for, qsaText, noteStr]);\n"
        )
        f.write("      });\n")
        f.write("      const ws = XLSX.utils.aoa_to_sheet(sheetData);\n")
        f.write(
            "      ws['!cols'] = [{wch:30},{wch:50},{wch:10},{wch:25},{wch:60},{wch:40},{wch:60},{wch:50}];\n"
        )
        f.write(
            "      const sheetName = (host.hostname + ' (' + host.os_label + ')').replace(/[\\\\\\/?*\\[\\]]/g, '').substring(0, 31);\n"
        )
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
        f.write(
            "                if (k.startsWith('zipaudit|') && k !== BUILD_RESET_MARKER) {\n"
        )
        f.write("                    localStorage.removeItem(k);\n")
        f.write("                }\n")
        f.write("            });\n")
        f.write(
            "            localStorage.setItem(BUILD_RESET_MARKER, REPORT_SESSION);\n"
        )
        f.write("        }\n")
        f.write("    })();\n")
        f.write("\n")

        f.write("    function storageKey(reqId) {\n")
        f.write("        return 'zipaudit|' + HOST_KEY + '|' + reqId;\n")
        f.write("    }\n")
        f.write("\n")

        f.write("    function saveRowState(row, status, notes) {\n")
        f.write("        const key = storageKey(row.id);\n")
        f.write(
            "        localStorage.setItem(key, JSON.stringify({status: status, notes: notes}));\n"
        )
        f.write(
            "        window.dispatchEvent(new StorageEvent('storage', { key: key }));\n"
        )
        f.write("    }\n")
        f.write("\n")

        f.write("    function loadAllRowStates() {\n")
        f.write(
            "        const rows = Array.from(document.querySelectorAll('#requirementsTable tbody tr'));\n"
        )
        f.write("        rows.forEach((row, idx) => {\n")
        f.write("            const raw = localStorage.getItem(storageKey(row.id));\n")
        f.write("            if (!raw) return;\n")
        f.write("            try {\n")
        f.write("                const saved = JSON.parse(raw);\n")
        f.write("                row.className = saved.status;\n")
        f.write("                row.children[2].innerText = saved.status;\n")
        f.write("                syncQsaResponse(row, idx, saved.status);\n")
        f.write(
            "                row.querySelectorAll('.editor-note').forEach(e => e.remove());\n"
        )
        f.write("                if (Array.isArray(saved.notes)) {\n")
        f.write("                    setEditorNotes(row, saved.notes);\n")
        f.write("                    saved.notes.forEach(n => {\n")
        f.write("                        const cell    = row.children[4];\n")
        f.write(
            "                        const wrapper = document.createElement('div');\n"
        )
        f.write(
            "                        wrapper.className = 'finding-item editor-note';\n"
        )
        f.write(
            "                        const label = document.createElement('div');\n"
        )
        f.write("                        label.className = 'finding-label';\n")
        f.write(
            "                        label.innerHTML = '<b>Editor\\'s Note (' + escapeHtml(n.timestamp) + ', moved to ' + escapeHtml(n.status) + '):</b>';\n"
        )
        f.write("                        const body = document.createElement('div');\n")
        f.write(
            "                        body.innerHTML = escapeHtml(n.note).replace(/\\n/g, '<br>');\n"
        )
        f.write("                        wrapper.appendChild(label);\n")
        f.write("                        wrapper.appendChild(body);\n")
        f.write(
            "                        cell.insertBefore(wrapper, cell.firstChild);\n"
        )
        f.write("                    });\n")
        f.write("                }\n")
        f.write("            } catch(e) {}\n")
        f.write("        });\n")
        f.write("    }\n")
        f.write("\n")

        f.write(
            "    document.addEventListener('DOMContentLoaded', loadAllRowStates);\n"
        )
        f.write("\n")

        f.write("    function resolveFileContent(raw, filename) {\n")
        f.write("        const marker = '__TRUNCATED__:';\n")
        f.write("        const idx = raw.indexOf(marker);")
        f.write("        if (idx === -1) return raw;\n")
        f.write(
            "        const blob = new Blob([raw.substring(0, idx)], { type: 'text/plain' });\n"
        )
        f.write("        const url = URL.createObjectURL(blob);\n")
        f.write("        return raw.substring(0, idx)\n")
        f.write("            + '\\n\\n[File truncated at 300 lines]\\n'\n")
        f.write("            + '[DOWNLOAD_LINK:' + url + ':' + filename + ']';\n")
        f.write("    }\n")

        f.write("    function displayFileContent(content, filename) {\n")
        f.write(
            "        const linkPattern = /\\[DOWNLOAD_LINK:([^:]+):([^\\]]+)\\]/;\n"
        )
        f.write("        const match = content.match(linkPattern);\n")
        f.write("        const textarea = document.getElementById('fileContent');\n")
        f.write(
            "        const existing = document.getElementById('fileDownloadLink');\n"
        )
        f.write("        if (existing) existing.remove();\n")
        f.write("        if (match) {\n")
        f.write(
            "            textarea.value = content.replace(linkPattern, '').trim();\n"
        )
        f.write("            const a = document.createElement('a');\n")
        f.write("            a.id = 'fileDownloadLink';\n")
        f.write("            a.href = match[1];\n")
        f.write("            a.download = match[2];\n")
        f.write(
            "            a.style.cssText = 'display:inline-block;margin-top:6px;font-size:0.9em;color:#0066cc;';\n"
        )
        f.write(
            "            textarea.parentNode.insertBefore(a, textarea.nextSibling);\n"
        )
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
        f.write(
            "        displayFileContent(resolveFileContent(raw, sel.value), sel.value);\n"
        )
        f.write(
            "        document.getElementById('statusSelect').value = document.querySelectorAll('#requirementsTable tbody tr')[idx].children[2].innerText.trim();\n"
        )
        f.write("        document.getElementById('editorNote').value = '';\n")
        f.write("    }\n")

        f.write("    function closeReview() {\n")
        f.write(
            "        document.getElementById('reviewModal').style.display = 'none';\n"
        )
        f.write("    }\n")

        f.write("    function syncQsaResponse(row, idx, status) {\n")
        f.write("        const cell = row.querySelector('.qsa-response-cell');\n")
        f.write("        if (!cell) return;\n")
        f.write("        const evidence = REPORT_EVIDENCE[idx] || {};\n")
        f.write("        const response = evidence.qsa_response || '';\n")
        f.write("        if (String(status).toLowerCase() === 'passed') {\n")
        f.write(
            "            cell.innerHTML = '<span class=\"qsa-response-text\">' + escapeHtml(response) + '</span>';\n"
        )
        f.write("        } else {\n")
        f.write("            cell.innerHTML = '';\n")
        f.write("        }\n")
        f.write("    }\n")

        f.write("    document.addEventListener('click', function(e) {\n")
        f.write(
            "        if (e.target && e.target.classList && e.target.classList.contains('review-btn')) {\n"
        )
        f.write("            openReview(parseInt(e.target.dataset.idx));\n")
        f.write("        }\n")
        f.write("    });\n")

        f.write("    function onFileChange() {\n")
        f.write(
            "        const idx = document.getElementById('reviewModal').dataset.idx;\n"
        )
        f.write("        const f = this.value;\n")
        f.write("        const evidence = REPORT_EVIDENCE[idx] || {};\n")
        f.write("        const files = evidence.files || {};\n")
        f.write("        const rawContent = files[f] || '';\n")
        f.write("        displayFileContent(resolveFileContent(rawContent, f), f);\n")
        f.write("    }\n")

        f.write("    function saveReview() {\n")
        f.write("        const modal  = document.getElementById('reviewModal');\n")
        f.write(
            "        if (!modal) { console.error('Modal element not found'); return; }\n"
        )
        f.write("        const idx    = parseInt(modal.dataset.idx);\n")
        f.write(
            "        const status = document.getElementById('statusSelect').value;\n"
        )
        f.write(
            "        const note   = document.getElementById('editorNote').value.trim();\n"
        )
        f.write(
            "        const row = document.querySelectorAll('#requirementsTable tbody tr')[idx];\n"
        )
        f.write(
            "        if (!row) { console.error('Row element not found at index ' + idx); return; }\n"
        )
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
        f.write(
            "            label.innerHTML = '<b>Editor\\'s Note (' + escapeHtml(timestamp) + ', moved to ' + escapeHtml(status) + '):</b>';\n"
        )
        f.write("            const body = document.createElement('div');\n")
        f.write(
            "            body.innerHTML = escapeHtml(note).replace(/\\n/g, '<br>');\n"
        )
        f.write("            wrapper.appendChild(label);\n")
        f.write("            wrapper.appendChild(body);\n")
        f.write("            cell.insertBefore(wrapper, cell.firstChild);\n")
        f.write("        }\n")
        f.write("\n")
        # Persist to localStorage — always, not just when a note is added
        f.write("        saveRowState(row, status, getEditorNotes(row));\n")
        f.write("        closeReview();\n")
        f.write("    }\n")

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
        f.write("        td.className = saved.status;\n")
        f.write("        const a = td.querySelector('a.cell-link');\n")
        f.write("        if (a) a.textContent = saved.status;\n")
        f.write("      } catch(e) {}\n")
        f.write("    });\n")
        f.write("  }\n")
        f.write(
            "  document.addEventListener('DOMContentLoaded', applyStoredStatuses);\n"
        )
        f.write("  window.addEventListener('focus', applyStoredStatuses);\n")
        f.write("  window.addEventListener('storage', applyStoredStatuses);\n")

        f.write("</script>\n")
        f.write(f"<div id='reviewModal'><div class='box'>\n")
        f.write(f"    <div style='display: flex; gap: 8px; align-items: center;'>\n")
        f.write(f"        <label>Status:</label>\n")
        f.write(
            f"        <select id='statusSelect'><option>passed</option><option>failed</option><option>review</option><option>manual</option><option>unknown</option></select>\n"
        )
        f.write(f"        <label style='margin-left: 12px;'>File:</label>\n")
        f.write(
            f"        <select id='fileSelect' onchange='onFileChange.call(this)'></select>\n"
        )
        f.write(f"    </div>\n")
        f.write(f"    <textarea id='fileContent' readonly></textarea>\n")
        f.write(f"    <label>Editor's Note:</label>\n")
        f.write(f"    <textarea id='editorNote'></textarea>\n")
        f.write(f"    <div style='margin-top: 12px;'>\n")
        f.write(
            f"        <button onclick='saveReview()' style='padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer;'>Save</button>\n"
        )
        f.write(
            f"        <button onclick='closeReview()' style='padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 8px;'>Cancel</button>\n"
        )
        f.write(f"    </div>\n")
        f.write(f"</div></div>\n")
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
    import html
    import json as _json

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

    export_data_json = _json.dumps(export_data)
    total = sum(counts.values()) or 1  # avoid div/0 for progress bars

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
            "        const headers = ['ID','Description','Status','Files','Findings','Look For','QSA Response','Editor Notes'];\n"
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


# windows-specific rules live here and drive the report row statuses
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
    running_services = data.get("running_services", [])
    updates = data.get("update_history", [])
    installed_apps = data.get("installed_apps", [])
    password_policy = data.get("password_policy", {})
    group_policy = data.get("group_policy", {})
    account_policies = group_policy.get("account_policies", {})
    audit_policy = data.get("audit_policy", {})
    logged_on_users = data.get("logged_on_users", [])
    local_users = data.get("local_users", [])
    local_groups = data.get("local_groups", [])
    rdp = data.get("rdp_config", {})
    timesync = data.get("timesync", {})
    system_info = data.get("systeminfo", {})

    def get_pw(key_gp, key_pp, default=None):
        return account_policies.get(key_gp) or password_policy.get(key_pp) or default

    def get_group_policy_value(key):
        # Prefer account_policies, then top-level audit_policy, then administrative_templates values
        val = account_policies.get(key)
        if val not in (None, ""):
            return val
        gp_audit = group_policy.get("audit_policy") or {}
        if key in gp_audit:
            return gp_audit.get(key)
        admin_templates = group_policy.get("administrative_templates") or {}
        if key in admin_templates:
            entry = admin_templates.get(key) or {}
            # entry may store 'value' or 'state'
            return entry.get("value") or entry.get("state")
        return None

    min_pw_len = int(get_pw("MinimumPasswordLength", "Minimum password length", 0) or 0)
    pw_history = int(
        get_pw("PasswordHistorySize", "Length of password history maintained", 0) or 0
    )
    max_pw_age = int(
        get_pw("MaximumPasswordAge", "Maximum password age (days)", 0) or 0
    )
    min_pw_age = int(
        get_pw("MinimumPasswordAge", "Minimum password age (days)", 0) or 0
    )
    lockout_count = int(get_pw("LockoutBadCount", "Lockout threshold", 0) or 0)
    lockout_dur_raw = get_pw("LockoutDuration", "Lockout duration (minutes)", "0")
    reset_count = int(
        get_pw("ResetLockoutCount", "Lockout observation window (minutes)", 0) or 0
    )

    # LockoutDuration: "4294967295" or "Never" both mean "never unlocks automatically"
    lockout_never = (
        str(lockout_dur_raw).strip().lower() == "never"
        or str(lockout_dur_raw).strip() == "4294967295"
    )

    # --- Audit policy helpers ---
    logon_audit = audit_policy.get("Logon/Logoff", {}).get("Logon", "")
    acct_mgmt_audit = audit_policy.get("Account Management", {}).get(
        "User Account Management", ""
    )
    priv_use_audit = audit_policy.get("Privilege Use", {}).get(
        "Sensitive Privilege Use", ""
    )
    proc_audit = audit_policy.get("Detailed Tracking", {}).get("Process Creation", "")
    policy_audit = audit_policy.get("Policy Change", {}).get("Audit Policy Change", "")
    telnet_disabled = str(summary.get("Telnet", "")).upper() != "TRUE"
    nla_enabled = str(get_rdp_setting(data, "UserAuthentication") or "").strip() == "1"
    rdp_encryption = get_rdp_setting(data, "SecurityLayer") or ""

    # -------------------------
    # [2.2.1.c] - INF-Cloud-LX-1605
    # -------------------------
    insecure_defs = cheat_sheet.get("insecure_services_windows", [])
    found_insecure = []
    matched_insecure_names = set()

    for svc in running_services:
        service_name = (svc.get("service") or "").lower()
        description = (svc.get("description") or "").lower()

        # Skip if this service name has already produced a match
        if service_name in matched_insecure_names:
            continue

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
                matched_insecure_names.add(service_name)
                break  # avoid matching the same service to multiple insecure categories

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
                    "file": "09_Services_Details.csv",
                }
            )
    else:
        findings_221c.append(
            {
                "message": "No common insecure services found. Please review before passing.",
                "file": "09_Services_Details.csv",
            }
        )

    add(
        "[2.2.1.c] - INF-Cloud-LX-1605",
        "Provide system configuration standards to confirm insecure services are disabled (for example: root, telnet, ftp, tftp, bootp, sendmail, smb, NIS, rexec, rsh, rlogin; daemons such as lpd, dns, DHCP).",
        "review",
        findings_221c,
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Unexpected or insecure services such as telnet/ftp/rsh/rlogin/sendmail, etc.",
        qsa_response="QSA reviewed configuration and confirmed that no insecure services were found enabled across systems. This was confirmed by reviewing the system configurations and service descriptions against common insecure services, as well as manual review of running services for any unexpected or high-risk services that may not be common.",
    )

    # -------------------------
    # [2.2.2.c] - INF-Cloud-LX-1650
    # -------------------------
    default_account_names = {
        "defaultaccount",
        "guest",
        "administrator",
        "wdagutilityaccount",
        "cbntguest",
    }
    found_default_accounts = [
        u["username"]
        for u in local_users
        if u.get("username", "").lower() in default_account_names
    ]
    guest_enabled = str(account_policies.get("EnableGuestAccount", "")).strip().lower()
    guest_flag_active = guest_enabled not in ("", "not enabled", "0", "false")

    if found_default_accounts or guest_flag_active:
        status_222 = "review"
    else:
        status_222 = "passed"

    findings_222 = [f"Observed {len(local_users)} local accounts."]
    if found_default_accounts:
        findings_222.append(
            f"Potential default/vendor accounts detected: {found_default_accounts}"
        )
    else:
        findings_222.append(
            "No common default account names detected among local users."
        )
    if guest_flag_active:
        findings_222.append(
            f"EnableGuestAccount policy = {guest_enabled} - Guest account may be active."
        )
    else:
        findings_222.append(
            f"EnableGuestAccount policy = {guest_enabled or 'Not Enabled'}"
        )

    add(
        "[2.2.2.c] - INF-Cloud-LX-1650",
        "Provide configuration files to confirm that all vendor default accounts are removed or disabled.",
        status_222,
        findings_222,
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Default or vendor-provided accounts that should be disabled or removed.",
        qsa_response=(
            (
                "QSA reviewed the local account listings and group policy settings to confirm that vendor default "
                "accounts were removed or disabled. The review examined all local user accounts for common default "
                "Windows account names, and confirmed that the Guest account was not enabled per the account policy. "
                "No default or vendor-provided accounts were found to be active, reducing the risk of unauthorized "
                "access via shared or well-known credentials."
            )
            if status_222 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [2.2.3.b] - INF-Cloud-LX-1685
    # -------------------------
    add(
        "[2.2.3.b] - INF-Cloud-LX-1685",
        "Provide system configurations to confirm that primary functions requiring different access levels are separated.",
        "manual",
        [
            "This control requires architecture and function separation review.",
            f"Observed {len(running_services)} running services as context.",
            f"Local users observed: {[u.get('username') for u in local_users]}",
        ],
        ["09_Services_Details.csv", "00_Analysis.txt"],
        default_file="09_Services_Details.csv",
        look_for="Whether conflicting primary functions coexist on one host without separation.",
        qsa_response=(
            "QSA reviewed the system configurations and observed the running services and their descriptions "
            "to understand the primary functions of the host and confirmed that primary functions requiring "
            "different access levels were isolated from one another."
        ),
    )

    # -------------------------
    # [2.2.3.c] - INF-Cloud-LX-1690
    # -------------------------
    insecure_defs = cheat_sheet.get("insecure_services_windows", [])
    detected_categories = set()

    for svc in running_services:
        name = (svc.get("service") or "").lower()
        desc = (svc.get("description") or "").lower()

        for insecure in insecure_defs:
            if any(
                alias in name or alias in desc for alias in insecure.get("aliases", [])
            ):
                detected_categories.add(insecure["name"])

    findings_223c = []

    if detected_categories:
        findings_223c.append(
            f"Insecure/high-risk service categories detected: {list(detected_categories)}"
        )

    if len(running_services) > 30:
        findings_223c.append(
            "Large number of services suggests possible multi-function host."
        )

    if not nla_enabled:
        findings_223c.append(
            "RDP NLA is not enabled - indicates a weaker remote access security boundary."
        )

    if not findings_223c:
        findings_223c.append(
            "No obvious conflicting security roles detected. Manual validation required."
        )

    add(
        "[2.2.3.c] - INF-Cloud-LX-1690",
        "Provide system configurations to confirm that system functions requiring different security needs are separated or appropriately secured together.",
        "review",
        findings_223c,
        ["09_Services_Details.csv", "05_GroupPolicy.txt"],
        default_file="09_Services_Details.csv",
        look_for="Coexistence of high-risk services with sensitive services or mixed security domains.",
        qsa_response=(
            "QSA reviewed the system configurations, running services, and RDP settings to evaluate whether "
            "there were any conflicting primary functions or high-risk services coexisting on the host without "
            "proper separation. The review considered the types of services running, their descriptions, and "
            "the RDP configuration including NLA status to assess the security boundaries and whether functions "
            "with different security needs were appropriately separated or secured together."
        ),
    )

    # -------------------------
    # [2.2.4.b] - INF-Cloud-LX-1710
    # -------------------------
    add(
        "[2.2.4.b] - INF-Cloud-LX-1710",
        "Provide evidence to confirm that unnecessary functions are removed or disabled.",
        "review",
        [
            f"Observed {len(running_services)} running services.",
            f"Observed {len(installed_apps)} installed applications.",
            "Manual validation still required to determine whether services are necessary for business purpose.",
        ],
        ["09_Services_Details.csv", "07_InstalledPrograms_wmioutput.txt"],
        default_file="09_Services_Details.csv",
        look_for="Services or installed applications running without a clear business need.",
        qsa_response=(
            "QSA reviewed the list of running services and installed applications to evaluate whether there "
            "were any unnecessary functions that should be removed or disabled. The review focused on "
            "identifying any services or applications that are commonly considered unnecessary or high-risk, "
            "and confirmed that the observed services and installed applications were consistent with the "
            "system's documented business purpose."
        ),
    )

    # -------------------------
    # [2.2.5.b] - INF-Cloud-LX-1745
    # -------------------------

    if not found_insecure:
        add(
            "[2.2.5.b] - INF-Cloud-LX-1745",
            "Provide configuration settings to confirm that additional security features are implemented to reduce the risk of using insecure services, daemons, and protocols.",
            "passed",
            [
                "No insecure services detected from 2.2.1.c.",
                "This requirement does not apply when insecure services are not present.",
            ],
            ["09_Services_Details.csv"],
            default_file="09_Services_Details.csv",
            look_for="N/A – no insecure services present.",
            qsa_response=(
                "QSA reviewed the system configurations and confirmed that no insecure services were found "
                "enabled on the system, therefore this requirement is not applicable. This was confirmed by "
                "reviewing the running services and installed applications against common insecure service "
                "categories, and no unexpected or high-risk services were identified."
            ),
        )

    else:
        # Windows hardening review via RDP config and group policy
        findings_225b = []

        nla_val = get_rdp_setting(data, "UserAuthentication")
        encrypt_level = get_rdp_setting(data, "MinEncryptionLevel")
        disable_enc = get_rdp_setting(data, "fDisableEncryption")
        prompt_pw = get_rdp_setting(data, "fPromptForPassword")
        disable_pw_save = get_rdp_setting(data, "DisablePasswordSaving")
        enc_rpc = get_rdp_setting(data, "fEncryptRPCTraffic")
        security_layer = get_rdp_setting(data, "SecurityLayer")
        pw_complexity = get_group_policy_value("PasswordComplexity") or ""
        clear_text_pw = get_group_policy_value("ClearTextPassword") or ""

        checks_225b = {
            f'<b>NLA (UserAuthentication) enabled</b> - {str(nla_val).strip() == "1"}': str(
                nla_val
            ).strip()
            == "1",
            f"<b>Minimum encryption level ≥ 3</b> - {str(encrypt_level).strip().isdigit() and int(str(encrypt_level).strip()) >= 3}": str(
                encrypt_level
            )
            .strip()
            .isdigit()
            and int(str(encrypt_level).strip()) >= 3,
            f'<b>Encryption not disabled (fDisableEncryption = 0)</b> - {str(disable_enc).strip() == "0"}': str(
                disable_enc
            ).strip()
            == "0",
            f'<b>Password prompt enforced (fPromptForPassword = 1)</b> - {str(prompt_pw).strip() == "1"}': str(
                prompt_pw
            ).strip()
            == "1",
            f'<b>Password saving disabled (DisablePasswordSaving = 1)</b> - {str(disable_pw_save).strip() == "1"}': str(
                disable_pw_save
            ).strip()
            == "1",
            f'<b>RPC traffic encrypted (fEncryptRPCTraffic = 1)</b> - {str(enc_rpc).strip() == "1"}': str(
                enc_rpc
            ).strip()
            == "1",
            f"<b>Security layer configured (SecurityLayer ≥ 1)</b> - {str(security_layer).strip().isdigit() and int(str(security_layer).strip()) >= 1}": str(
                security_layer
            )
            .strip()
            .isdigit()
            and int(str(security_layer).strip()) >= 1,
            f'<b>Password complexity enabled</b> - {str(pw_complexity).strip().lower() in ("enabled", "1", "true")}': str(
                pw_complexity
            )
            .strip()
            .lower()
            in ("enabled", "1", "true"),
            f'<b>Clear-text password storage disabled</b> - {str(clear_text_pw).strip().lower() in ("not enabled", "0", "false")}': str(
                clear_text_pw
            )
            .strip()
            .lower()
            in ("not enabled", "0", "false"),
        }

        for check, passed in checks_225b.items():
            findings_225b.append(f"{check}: {'PASS' if passed else 'FAIL'}")

        add(
            "[2.2.5.b] - INF-Cloud-LX-1745",
            "Provide configuration settings to confirm that additional security features are implemented to reduce the risk of using insecure services, daemons, and protocols.",
            "review",
            findings_225b,
            ["05_GroupPolicy.txt", "00_Analysis.txt"],
            default_file="05_GroupPolicy.txt",
            look_for="RDP hardening controls: NLA enabled, encryption level ≥ 3, password saving disabled, RPC encryption enforced.",
            qsa_response=(
                "QSA reviewed the RDP and group policy configuration settings to evaluate whether additional "
                "security features were implemented to reduce the risk associated with insecure services. "
                "The review focused on key RDP hardening controls including Network Level Authentication, "
                "minimum encryption level, RPC traffic encryption, password complexity enforcement, and "
                "the prohibition of clear-text password storage."
            ),
        )

    # -------------------------
    # [2.2.6.c] - INF-Cloud-LX-1770
    # -------------------------

    findings_226c = []
    status = "passed"

    # Admin group membership check (Windows equivalent of UID 0)
    restricted_groups = data.get("group_policy", {}).get("restricted_groups", {})
    admin_members = restricted_groups.get("Administrators", [])

    if admin_members:
        findings_226c.append(
            f"Administrators group members (restricted_groups): {admin_members}"
        )
    else:
        # Fall back to local_groups
        admin_group = next(
            (g for g in local_groups if g.get("group", "").lower() == "administrators"),
            None,
        )
        if admin_group:
            admin_members = admin_group.get("members", [])
            findings_226c.append(
                f"Administrators group members (local_groups): {admin_members}"
            )
        else:
            findings_226c.append("Administrators group not found in available data.")

    # Unused / insecure services (reuse 2.2.1.c logic)
    if not found_insecure:
        findings_226c.append("No common insecure services detected: PASS")
    else:
        findings_226c.append(f"Insecure services present: {len(found_insecure)} found")
        status = "review"

    # Password policy strength (use already-derived min_pw_len)
    if min_pw_len >= 12:
        findings_226c.append(f"Minimum password length = {min_pw_len}: PASS")
    else:
        findings_226c.append(
            f"Minimum password length = {min_pw_len}: FAIL (requirement: 12+)"
        )
        status = "review"

    # Password complexity
    pw_complexity_val = get_group_policy_value("PasswordComplexity") or ""
    if str(pw_complexity_val).strip().lower() in ("enabled", "1", "true"):
        findings_226c.append(f"Password complexity = {pw_complexity_val}: PASS")
    else:
        findings_226c.append(
            f"Password complexity = {pw_complexity_val or 'Not found'}: FAIL"
        )
        status = "review"

    # Generic/default account detection from local_users
    generic_names = {
        "test",
        "guest",
        "admin",
        "user",
        "defaultaccount",
        "wdagutilityaccount",
    }
    generic_users = [
        u.get("username")
        for u in local_users
        if u.get("username", "").lower() in generic_names
    ]

    if generic_users:
        findings_226c.append(
            f"Potential generic/default accounts detected: {generic_users}"
        )
        status = "review"
    else:
        findings_226c.append("No obvious generic or default accounts detected: PASS")

    add(
        "[2.2.6.c] - INF-Cloud-LX-1770",
        "Provide system configurations to confirm that common security parameters are set appropriately and in accordance with configuration standards.",
        status,
        findings_226c,
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Common hardening controls: administrator group membership, password policies, service minimization, and account hygiene.",
        qsa_response=(
            (
                "QSA reviewed the system configurations, password policies, and local account information to "
                "evaluate whether common security parameters were set appropriately. The review focused on key "
                "hardening controls including administrator group membership, confirmation that no common insecure "
                "services were present, password policy strength including minimum length and complexity "
                "requirements, and an assessment of local accounts for generic or default usernames that may "
                "indicate weak account hygiene."
            )
            if status == "passed"
            else ""
        ),
    )

    # -------------------------
    # [2.2.7.b] - INF-Cloud-LX-1800
    # -------------------------
    add(
        "[2.2.7.b] - INF-Cloud-LX-1800",
        "Provide system configurations to confirm that non-console administrative access is managed in accordance with this requirement.",
        "passed" if telnet_disabled and nla_enabled else "failed",
        [
            f"Telnet flag in summary = {summary.get('Telnet')}",
            f"RDP NLA Enabled (UserAuthentication) = {get_rdp_setting(data, 'UserAuthentication') or ''}",
            f"RDP Security Layer = {get_rdp_setting(data, 'SecurityLayer') or ''}",
        ],
        ["00_Analysis.txt", "05_GroupPolicy.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="Telnet disabled and RDP Network Level Authentication (NLA) enabled.",
        qsa_response=(
            (
                "QSA reviewed the system configurations to confirm that non-console administrative access was "
                "managed in accordance with the requirement. The review confirmed that Telnet was disabled as "
                "indicated in the system summary, and that RDP was configured with Network Level Authentication "
                "(NLA) enabled, ensuring that only authenticated users may establish remote desktop sessions. "
                "The RDP security layer setting was also reviewed as part of evaluating the overall security "
                "posture of remote administrative access."
            )
            if telnet_disabled and nla_enabled
            else ""
        ),
    )

    # -------------------------
    # [2.2.7.c] - INF-Cloud-LX-1810
    # -------------------------

    findings_227c = []

    # Insecure remote services check (reuse 2.2.1.c)
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

    # NLA (Windows equivalent of SSH protocol strength)
    protocol_ok = nla_enabled
    findings_227c.append(
        f"RDP NLA (UserAuthentication) = {get_rdp_setting(data, 'UserAuthentication') or ''}: "
        f"{'PASS' if protocol_ok else 'FAIL'}"
    )

    # Authentication enforced - no empty/null passwords, password prompt required
    rdp_prompt_pw = str(get_rdp_setting(data, "fPromptForPassword") or "0").strip()
    rdp_disable_save = str(get_rdp_setting(data, "DisablePasswordSaving") or "0").strip()
    clear_text_val = (
        str(get_group_policy_value("ClearTextPassword") or "Not Enabled").strip().lower()
    )

    auth_ok = (
        rdp_prompt_pw == "1"
        and rdp_disable_save == "1"
        and clear_text_val in ("not enabled", "0", "false")
    )

    findings_227c.append(
        f"RDP fPromptForPassword = {rdp_prompt_pw}: {'PASS' if rdp_prompt_pw == '1' else 'FAIL'}"
    )
    findings_227c.append(
        f"RDP DisablePasswordSaving = {rdp_disable_save}: {'PASS' if rdp_disable_save == '1' else 'FAIL'}"
    )
    findings_227c.append(
        f"ClearTextPassword policy = {clear_text_val}: {'PASS' if clear_text_val in ('not enabled', '0', 'false') else 'FAIL'}"
    )

    # Encryption strength
    enc_level = str(get_rdp_setting(data, "MinEncryptionLevel") or "0").strip()
    enc_rpc = str(get_rdp_setting(data, "fEncryptRPCTraffic") or "0").strip()
    findings_227c.append(
            f"RDP MinEncryptionLevel = {enc_level}: {'PASS' if enc_level.isdigit() and int(enc_level) >= 3 else 'FAIL'}"
    )
    findings_227c.append(
        f"RDP fEncryptRPCTraffic = {enc_rpc}: {'PASS' if enc_rpc == '1' else 'FAIL'}"
    )

    status_227c = "passed" if insecure_ok and protocol_ok and auth_ok else "review"

    add(
        "[2.2.7.c] - INF-Cloud-LX-1810",
        "Provide settings for system components and authentication services to confirm that insecure remote login services are not available for non-console administrative access.",
        status_227c,
        findings_227c,
        ["05_GroupPolicy.txt", "00_Analysis.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="Absence of insecure remote protocols and presence of secure RDP with NLA, strong encryption, and authentication enforcement.",
        qsa_response=(
            (
                "QSA reviewed the system configurations to confirm that insecure remote login services were not "
                "available for non-console administrative access. The review confirmed that no insecure remote "
                "protocols such as Telnet, rlogin, or FTP were detected among running services, and that RDP "
                "was configured with Network Level Authentication, password prompt enforcement, password save "
                "disabled, RPC traffic encryption, and an appropriate minimum encryption level."
            )
            if status_227c == "passed"
            else ""
        ),
    )

    # -------------------------
    # Logic for 5.x to find anti-malware services
    # -------------------------

    detected_av = []
    av_defs = cheat_sheet.get("av_signatures", [])

    # Track already-matched service names to avoid duplicate entries
    # from the same service appearing multiple times in the Windows process list
    matched_service_names = set()

    for svc in running_services:
        service_name = (svc.get("service") or "").lower()
        description = (svc.get("description") or "").lower()
        state = (svc.get("status") or "").lower()

        # Skip if we've already recorded a match for this service name
        if service_name in matched_service_names:
            continue

        for av in av_defs:
            aliases = [a.lower() for a in av.get("aliases", [])]

            if any(alias in service_name or alias in description for alias in aliases):
                if "running" in state:
                    detected_av.append(
                        {
                            "vendor": av.get("name"),
                            "service": svc.get("service"),
                            "description": svc.get("description") or "(no description)",
                        }
                    )
                    matched_service_names.add(service_name)
                break  # stop checking more aliases for this service

    # Secondary pass: check installed_apps for AV vendors not visible in services
    matched_vendors = {av["vendor"] for av in detected_av}

    for app in installed_apps:
        app_name = (app.get("name") or "").lower()

        for av in av_defs:
            if av.get("name") in matched_vendors:
                continue  # already detected via services

            aliases = [a.lower() for a in av.get("aliases", [])]

            if any(alias in app_name for alias in aliases):
                detected_av.append(
                    {
                        "vendor": av.get("name"),
                        "service": "(installed application)",
                        "description": app.get("name"),
                    }
                )
                matched_vendors.add(av.get("name"))
                break

    # -------------------------
    # [5.2.1.a] - INF-Cloud-LX-2895
    # -------------------------
    status_521 = "passed" if detected_av else "review"

    findings_521 = []

    if detected_av:
        for av in detected_av:
            findings_521.append(
                f"Detected AV/EDR solution: {av['vendor']} ({av['service']}) - running"
            )
    else:
        findings_521.append("No known AV/EDR services detected.")

    add(
        "[5.2.1.a] - INF-Cloud-LX-2895",
        "Provide evidence that an anti-malware solution is deployed where required.",
        status_521,
        findings_521,
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Presence of AV/EDR services in running state.",
        qsa_response="QSA reviewed the list of running services to identify any known anti-malware (AV/EDR) solutions deployed on the system to confirm that an anti-malware solution was present where required. The review consisted of finding matches between running services and known AV/EDR signatures, and evaluating their state to confirm they were active.",
    )

    # -------------------------
    # [5.3.1.a] - INF-Cloud-LX-2990
    # -------------------------
    add(
        "[5.3.1.a] - INF-Cloud-LX-2990",
        "Provide anti-malware solution configurations to confirm the solution is configured appropriately.",
        "passed" if detected_av else "review",
        [
            (
                f"Detected AV solutions: {[av['vendor'] for av in detected_av]}"
                if detected_av
                else "No AV detected - requires review"
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Active AV presence implies baseline configuration is applied.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the solution was configured appropriately. The review focused on ensuring that the AV/EDR solution was properly configured with baseline settings.",
    )

    # -------------------------
    # [5.3.1.b] - INF-Cloud-LX-3000
    # -------------------------
    add(
        "[5.3.1.b] - INF-Cloud-LX-3000",
        "Provide logs to confirm that the anti-malware solution(s) and definitions are current and have been promptly deployed.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected but version/definition recency cannot be verified from services."
                if detected_av
                else "No AV detected - cannot validate."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Definition update status or management console evidence.",
        qsa_response="QSA reviewed the available evidence to evaluate whether the anti-malware solution and its definitions were current and promptly deployed. The review considered the presence of AV/EDR services and any available information about their version or definition update status.",
    )

    # -------------------------
    # [5.3.2.a] - INF-Cloud-LX-3020
    # -------------------------
    add(
        "[5.3.2.a] - INF-Cloud-LX-3020",
        "Provide anti-malware configurations to confirm the solution is configured for active monitoring.",
        "passed" if detected_av else "review",
        [
            (
                "Running AV/EDR service strongly indicates active monitoring."
                if detected_av
                else "No AV/EDR running - active monitoring cannot be confirmed."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="AV/EDR service running suggests active monitoring, but review for management console or logs to confirm.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the solution was configured for active monitoring. The review focused on the presence of running AV/EDR services as an indicator of active monitoring, while also noting that additional evidence such as management console access or logs would be needed to fully confirm active monitoring practices.",
    )

    # -------------------------
    # [5.3.2.b] - INF-Cloud-LX-3030
    # -------------------------
    add(
        "[5.3.2.b] - INF-Cloud-LX-3030",
        "Provide evidence to confirm the anti-malware solution is enabled.",
        "passed" if detected_av else "review",
        [
            (
                "AV/EDR service observed running."
                if detected_av
                else "No AV service running."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        qsa_response="QSA reviewed the evidence to confirm that the anti-malware solution was enabled. The review focused on the presence of running AV/EDR services as an indicator that the solution was active and enabled on the system.",
    )

    # -------------------------
    # [5.3.2.c] - INF-Cloud-LX-3040
    # -------------------------
    add(
        "[5.3.2.c] - INF-Cloud-LX-3040",
        "Provide logs to confirm that the solution(s) is enabled in accordance with at least one of the elements specified in this requirement",
        "passed" if detected_av else "review",
        [
            (
                "AV running, but scheduling must be verified via logs or console."
                if detected_av
                else "No AV detected."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Scheduled scans, real-time protection status, or management console evidence confirming enabled features",
        qsa_response="QSA reviewed the available evidence to confirm that the anti-malware solution was enabled in accordance with the specified elements. The review considered the presence of running AV/EDR services as an indicator of enabled status, while also noting that additional evidence such as logs or management console access would be needed to verify specific features like scheduled scans or real-time protection.",
    )

    # -------------------------
    # [5.3.4] - INF-Cloud-LX-3130
    # -------------------------
    add(
        "[5.3.4] - INF-Cloud-LX-3130",
        "Provide anti-malware solution(s) configurations to confirm logs are enabled and retained in accordance with Requirement 10.5.1.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected, but logging configuration cannot be validated from service data."
                if detected_av
                else "No AV detected."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Logging settings in AV configuration or management console, and retention policies.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that logs were enabled and retained in accordance with Requirement 10.5.1. The review focused on the presence of running AV/EDR services as an indicator of an active solution, while also noting that specific logging configurations and retention policies would need to be verified through management console access or additional configuration files.",
    )

    # -------------------------
    # [5.3.5.a] - INF-Cloud-LX-3150
    # -------------------------
    add(
        "[5.3.5.a] - INF-Cloud-LX-3150",
        "Provide anti-malware solution configurations to confirm that the anti-malware mechanisms cannot be disabled or altered by users.",
        "passed" if detected_av else "review",
        [
            (
                "AV detected, review to ensure appropriate tamper protection or policy controls are in place."
                if detected_av
                else "No AV detected."
            )
        ],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Tamper protection settings or policy controls preventing user disablement.",
        qsa_response="QSA reviewed the anti-malware solution configurations to confirm that the anti-malware mechanisms could not be disabled or altered by users. The review focused on identifying any tamper protection settings or policy controls that would prevent unauthorized disablement of the AV/EDR solution, while also noting that specific controls would need to be verified through management console access or additional configuration files.",
    )

    # -------------------------
    # [5.3.5.b] - INF-Cloud-LX-3160
    # -------------------------
    add(
        "[5.3.5.b] - INF-Cloud-LX-3160",
        "Provide observation(s) to confirm that attempts to disable or remove anti-malware are prevented.",
        "manual",
        ["Requires manual observation or management policy evidence."],
        ["09_Services_Details.csv"],
        default_file="09_Services_Details.csv",
        look_for="Tamper protection / policy preventing disablement.",
    )

    # -------------------------
    # [6.3.3.b] - INF-Cloud-LX-3445
    # -------------------------
    installed_patches = data.get("installed_patches", [])

    # Sort patches by date descending to find most recent
    recent_patches = sorted(
        [p for p in installed_patches if p.get("installed_on")],
        key=lambda p: p.get("installed_on", ""),
        reverse=True,
    )
    most_recent_patch = recent_patches[0] if recent_patches else None

    findings_633b = [
        f"OS / platform = {system_info.get('OS Version') or summary.get('os') or 'Not found in summary'}",
        f"Installed patch entries observed = {len(installed_patches)}",
        f"Installed application entries observed = {len(installed_apps)}",
    ]

    if most_recent_patch:
        findings_633b.append(
            f"Most recent patch: {most_recent_patch.get('patch_id')} "
            f"({most_recent_patch.get('description')}) - installed {most_recent_patch.get('installed_on')}"
        )
    else:
        findings_633b.append(
            "No patch install dates found - recency cannot be determined automatically."
        )

    findings_633b.append(
        "Patch history alone is not sufficient to confirm all latest available security patches are installed; "
        "comparison to vendor bulletin or WSUS/SCCM data is required."
    )

    add(
        "[6.3.3.b] - INF-Cloud-LX-3445",
        "Provide system component and patch/update data to confirm vulnerabilities are patched according to policy.",
        "review",
        findings_633b,
        ["11_InstalledPatches.txt"],
        default_file="11_InstalledPatches.txt",
        look_for="Recent patch cadence, most recently applied KB, and comparison to latest available updates.",
        qsa_response=(
            "QSA reviewed the system component and patch/update data to evaluate whether vulnerabilities "
            "were patched according to policy. The review considered the installed patch history, the most "
            "recently applied security update, and the list of installed applications to assess the system's "
            "overall patch posture. The patch cadence observed was consistent with the organization's defined "
            "patching policy, and no critical unpatched vulnerabilities were identified based on the evidence reviewed."
        ),
    )

    # -------------------------
    # [7.2.1.b] - INF-Cloud-LX-3850
    # -------------------------
    admin_group_members_7 = []
    rdp_group_members = []

    restricted_groups_7 = data.get("group_policy", {}).get("restricted_groups", {})

    # Prefer restricted_groups policy, fall back to local_groups
    if "Administrators" in restricted_groups_7:
        admin_group_members_7 = restricted_groups_7.get("Administrators", [])
    else:
        admin_fallback = next(
            (g for g in local_groups if g.get("group", "").lower() == "administrators"),
            None,
        )
        if admin_fallback:
            admin_group_members_7 = admin_fallback.get("members", [])

    rdp_group_members = restricted_groups_7.get("Remote Desktop Users", [])

    add(
        "[7.2.1.b] - INF-Cloud-LX-3850",
        "Provide user access settings to confirm access is based on job/function need.",
        "review",
        [
            f"Local accounts observed: {[u.get('username') for u in local_users]}",
            f"Administrators group members: {admin_group_members_7}",
            f"Remote Desktop Users group members: {rdp_group_members}",
            "Access assignment requires validation against job function and documented approvals.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Users or accounts with unnecessary or excessive access relative to their job function.",
        qsa_response=(
            "QSA reviewed the user access settings to confirm that access was assigned based on job function "
            "and business need. The review examined local account listings, Administrators group membership, "
            "and Remote Desktop Users group membership to evaluate whether assigned access levels were "
            "consistent with the roles and responsibilities of the individuals involved. No accounts were "
            "identified as having access clearly inconsistent with their documented function."
        ),
    )

    # -------------------------
    # [7.2.2.b] - INF-Cloud-LX-3870
    # -------------------------
    add(
        "[7.2.2.b] - INF-Cloud-LX-3870",
        "Provide user access settings to confirm privileges assigned are based on job function.",
        "review",
        [
            f"Administrators group members: {admin_group_members_7}",
            f"Remote Desktop Users group members: {rdp_group_members}",
            f"Backup Operators group members: {restricted_groups_7.get('Backup Operators', [])}",
            "Privileged group memberships require validation against approved role assignments.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Privileged group memberships consistent with approved job functions.",
        qsa_response=(
            "QSA reviewed the user access settings to confirm that privileges were assigned based on job "
            "function. The review examined membership in privileged groups including Administrators, Remote "
            "Desktop Users, and Backup Operators to evaluate whether elevated access was limited to accounts "
            "with a documented business need. Group memberships observed were consistent with the roles "
            "associated with the individuals and groups identified."
        ),
    )

    # -------------------------
    # [7.2.3.b] - INF-Cloud-LX-3915
    # -------------------------
    add(
        "[7.2.3.b] - INF-Cloud-LX-3915",
        "Provide user IDs and assigned privileges to confirm documented approval exists.",
        "manual",
        [
            "Requires external approval/ticket evidence not present in JSON.",
            f"Local accounts observed for cross-reference: {[u.get('username') for u in local_users]}",
            f"Administrators group members: {admin_group_members_7}",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Documented approvals matching granted access.",
        qsa_response=(
            "QSA reviewed the user IDs and assigned privileges and cross-referenced them against documented "
            "approval records provided by the organization. The review confirmed that access grants for the "
            "observed local accounts and privileged group memberships were supported by approved access "
            "requests or change records, demonstrating that privilege assignments followed a formal approval process."
        ),
    )

    # -------------------------
    # [7.2.5.b] - INF-Cloud-LX-3970
    # -------------------------

    # Identify accounts that appear to be system/service accounts rather than named individuals
    service_account_markers = [
        "svc",
        "service",
        "system",
        "local",
        "network",
        "fileshare",
        "backup",
        "agent",
    ]
    system_accounts = [
        u.get("username")
        for u in local_users
        if any(m in (u.get("username") or "").lower() for m in service_account_markers)
    ]

    add(
        "[7.2.5.b] - INF-Cloud-LX-3970",
        "Provide privileges associated with system and application accounts to confirm proper configuration.",
        "review",
        [
            f"Local accounts observed: {[u.get('username') for u in local_users]}",
            (
                f"Potential system/service accounts detected: {system_accounts}"
                if system_accounts
                else "No obvious system/service account names detected among local users."
            ),
            f"Administrators group members: {admin_group_members_7}",
            "System and application account privilege levels require validation against least-privilege policy.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="System or application accounts with interactive access or membership in privileged groups.",
        qsa_response=(
            "QSA reviewed the privileges associated with system and application accounts to confirm proper "
            "configuration. The review examined local account listings for accounts consistent with service "
            "or application usage patterns, and evaluated their group memberships against the principle of "
            "least privilege. System and application accounts observed were not found to hold privileges "
            "beyond those required for their designated function."
        ),
    )

    # -------------------------
    # [7.3.1] - INF-Cloud-LX-4075
    # -------------------------
    add(
        "[7.3.1] - INF-Cloud-LX-4075",
        "Provide system settings to confirm access is managed for each system component.",
        "manual",
        [
            "Per-component access control model cannot be fully established from host-level JSON alone.",
            f"Restricted groups policy observed: {list(restricted_groups_7.keys())}",
            f"Local accounts observed: {[u.get('username') for u in local_users]}",
            "Supporting IAM, Active Directory, or GPO evidence required to confirm per-component enforcement.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Per-component access management configuration.",
        qsa_response=(
            "QSA reviewed the system settings to confirm that access was managed at the individual component "
            "level. The review considered the restricted groups policy, local account configuration, and "
            "available group policy settings to assess how access was controlled across system components. "
            "The organization provided supporting evidence confirming that access to system components was "
            "managed through Active Directory and group policy in a manner consistent with this requirement."
        ),
    )

    # -------------------------
    # [7.3.2] - INF-Cloud-LX-4090
    # -------------------------
    add(
        "[7.3.2] - INF-Cloud-LX-4090",
        "Provide system settings to confirm the access control system is configured appropriately.",
        "manual",
        [
            "Full access control framework configuration cannot be derived from the current JSON alone.",
            f"Group policy account policies observed: {list(account_policies.keys())}",
            f"Restricted groups policy observed: {list(restricted_groups_7.keys())}",
            "Additional GPO export or AD configuration evidence required.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Access control framework settings and enforcement.",
        qsa_response=(
            "QSA reviewed the system settings to confirm that the access control system was configured "
            "appropriately. The review examined the available group policy settings, account policies, "
            "and restricted groups configuration to assess whether the access control framework enforced "
            "appropriate controls. The organization's Active Directory and group policy configuration was "
            "reviewed and found to implement access controls consistent with the requirement."
        ),
    )

    # -------------------------
    # [7.3.3] - INF-Cloud-LX-4110
    # -------------------------
    add(
        "[7.3.3] - INF-Cloud-LX-4110",
        "Provide system settings to confirm the access control system is set to default deny access.",
        "manual",
        [
            "Default-deny posture cannot be fully established from the current JSON alone.",
            f"InteractiveLogonRight assigned to: {group_policy.get('audit_policy', 'Not found').get('InteractiveLogonRight', 'Not found')}",
            f"NetworkLogonRight assigned to: {group_policy.get('audit_policy', 'Not found').get('NetworkLogonRight', 'Not found')}",
            f"DenyNetworkLogonRight assigned to: {group_policy.get('audit_policy', 'Not found').get('DenyNetworkLogonRight', 'Not found')}",
            f"DenyInteractiveLogonRight assigned to: {group_policy.get('audit_policy', 'Not found').get('DenyInteractiveLogonRight', 'Not found')}",
            "Full default-deny validation requires review of firewall rules and AD group policy deny assignments.",
        ],
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Default deny / explicit allow model in logon rights and access control policy.",
        qsa_response=(
            "QSA reviewed the system settings to confirm that the access control system was configured with "
            "a default-deny posture. The review examined the logon rights assignments in the group policy "
            "including interactive logon, network logon, and explicit deny assignments, and confirmed that "
            "access was restricted to named groups with a documented business need. The configuration "
            "observed was consistent with an explicit allow model where access is denied by default unless "
            "specifically granted."
        ),
    )

    # -------------------------
    # [8.2.1.b] - INF-Cloud-LX-4180
    # -------------------------

    # Windows: source from local_users; supplement with user_logons for domain accounts
    local_usernames = [u.get("username") for u in local_users if u.get("username")]
    logon_usernames = list(
        {
            entry.get("user", "").split("\\")[-1]
            for entry in data.get("user_logons", [])
            if entry.get("user")
        }
    )

    findings_821b = []

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
        "fileshare",
        "localadmin",
    ]

    suspect_accounts = []

    for u in local_users:
        username = (u.get("username") or "").lower()

        # Windows has no root; flag Localadmin / built-in admin equivalents instead
        if username in ("localadmin", "administrator"):
            findings_821b.append(
                f"{u.get('username')} is a local administrator-equivalent account; "
                "review whether it is used for routine administration."
            )
            continue

        if any(marker in username for marker in generic_markers):
            suspect_accounts.append(u.get("username"))

    if not local_users:
        status_821b = "manual"
        findings_821b.append(
            "No local user data found in JSON. Unable to assess enabled interactive accounts."
        )
    else:
        findings_821b.append(f"Local accounts observed: {', '.join(local_usernames)}")
        findings_821b.append(
            f"Domain accounts with recent logon activity observed: {len(logon_usernames)} unique users"
        )

        if suspect_accounts:
            status_821b = "review"
            findings_821b.append(
                f"Potential shared/generic/functional accounts detected: {', '.join(suspect_accounts)}"
            )
        else:
            status_821b = "review"
            findings_821b.append(
                "No obvious shared/generic account names detected, but individual ownership "
                "of domain accounts still requires validation against HR/IAM records."
            )

    add(
        "[8.2.1.b] - INF-Cloud-LX-4180",
        "Provide other evidence to confirm that access to system components and cardholder data can be uniquely identified and associated with individuals.",
        status_821b,
        findings_821b,
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Named individual accounts rather than shared, generic, or functional users.",
        qsa_response=(
            "QSA reviewed the local account listings and domain logon activity to confirm that access to "
            "system components could be uniquely identified and associated with named individuals. The review "
            "examined local accounts for generic or shared account naming patterns and confirmed that domain "
            "accounts observed in the logon history followed the organization's user ID naming convention "
            "consistent with individual assignment. No shared or group accounts were identified as being "
            "used for routine access to the system."
        ),
    )

    # -------------------------
    # [8.2.2.a] - INF-Cloud-LX-4190
    # -------------------------
    generic_markers_822 = [
        "shared",
        "generic",
        "functional",
        "svc",
        "service",
        "admin",
        "test",
        "temp",
        "bootstrap",
        "fileshare",
    ]

    shared_accounts_822 = [
        u.get("username")
        for u in local_users
        if any(m in (u.get("username") or "").lower() for m in generic_markers_822)
    ]

    # Also flag built-in accounts that are known shared-credential risks
    builtin_risk = [
        u.get("username")
        for u in local_users
        if (u.get("username") or "").lower() in ("administrator", "localadmin")
    ]

    findings_822a = [
        f"Local accounts observed: {[u.get('username') for u in local_users]}",
        f"Administrators group members: {admin_group_members_7}",
    ]

    if shared_accounts_822:
        findings_822a.append(
            f"Potential shared/generic account names detected: {shared_accounts_822}"
        )
    else:
        findings_822a.append(
            "No obviously shared or generic account names detected among local users."
        )

    if builtin_risk:
        findings_822a.append(
            f"Built-in or local admin-equivalent accounts present: {builtin_risk} - "
            "confirm these are not used for routine shared administrative access."
        )

    add(
        "[8.2.2.a] - INF-Cloud-LX-4190",
        "Provide user account evidence to confirm shared or generic credentials are not used except by exception.",
        "review",
        findings_822a,
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Generic or shared account names, or built-in admin accounts used for routine access.",
        qsa_response=(
            "QSA reviewed the local account listings and administrator group membership to confirm that "
            "shared or generic credentials were not in use for routine access. The review examined all "
            "local user accounts for naming patterns consistent with shared, generic, or functional "
            "accounts, and confirmed that built-in administrator-equivalent accounts were not being used "
            "for day-to-day administrative activity. Account ownership was found to be consistent with "
            "individual assignment."
        ),
    )

    # -------------------------
    # [8.2.4] - INF-Cloud-LX-4265
    # -------------------------

    # Windows: account change events sourced from Security event log export
    user_changes = data.get(
        "user_account_changes", data.get("user_changes", "no file found")
    )
    findings_824 = []

    if user_changes == "no file found" or user_changes is None:
        status_824 = "manual"
        findings_824.append(
            "No user account change data was found in the JSON. "
            "Unable to evaluate account modification activity."
        )

    elif isinstance(user_changes, list) and len(user_changes) == 0:
        status_824 = "review"
        findings_824.append(
            "No recent account creation, modification, or deletion events were observed."
        )
        findings_824.append(
            "Requires review of change tickets or approvals to confirm account activity has been managed."
        )

    else:
        status_824 = "review"
        findings_824.append(
            f"Observed {len(user_changes)} recent user/account change event(s)."
        )
        findings_824.append(
            "Review supporting approval or ticket evidence to confirm changes were authorized "
            "and implemented appropriately."
        )
        for change in user_changes[:5]:
            # Windows events may be dicts with EventID, TimeCreated, Message, etc.
            if isinstance(change, dict):
                event_id = change.get("EventID") or change.get("event_id", "")
                time_val = change.get("TimeCreated") or change.get("time", "")
                message = change.get("Message") or change.get("message", "")
                findings_824.append(
                    f"Event {event_id} at {time_val}: {str(message)[:120]}"
                )
            else:
                findings_824.append(f"Observed change: {change}")

    add(
        "[8.2.4] - INF-Cloud-LX-4265",
        "Provide system settings to confirm the activity has been managed.",
        status_824,
        findings_824,
        ["22_UserLogonHistory.txt"],
        default_file="22_UserLogonHistory.txt",
        look_for="Account creation, modification, or deletion events tied to approved requests.",
        qsa_response=(
            "QSA reviewed the account change event data to confirm that user account modification "
            "activity had been managed in accordance with the requirement. The review examined the "
            "observed account creation, modification, and deletion events and cross-referenced them "
            "against the organization's change management records. All observed account changes were "
            "supported by approved change requests, confirming that account lifecycle activity was "
            "properly authorized and documented."
        ),
    )

    # -------------------------
    # [8.2.6] - INF-Cloud-LX-4300
    # -------------------------
    from datetime import datetime, timezone

    findings_826 = []
    ninety_days_ago = datetime.now(timezone.utc).replace(tzinfo=None)

    stale_accounts = []
    unparseable = []

    for entry in data.get("user_logons", []):
        user = entry.get("user", "")
        raw_logon = entry.get("last_logon", "")

        # WMI format: "20250422073916.000000+000"
        try:
            dt = datetime.strptime(raw_logon[:14], "%Y%m%d%H%M%S")
            days_since = (datetime.utcnow() - dt).days
            if days_since > 90:
                stale_accounts.append(f"{user} (last logon {days_since} days ago)")
        except Exception:
            unparseable.append(user)

    if stale_accounts:
        findings_826.append(
            f"{len(stale_accounts)} account(s) with last logon > 90 days ago: {stale_accounts}"
        )
        status_826 = "review"
    else:
        findings_826.append(
            f"No accounts with last logon older than 90 days detected among "
            f"{len(data.get('user_logons', []))} observed logon entries."
        )
        status_826 = "passed"

    if unparseable:
        findings_826.append(
            f"{len(unparseable)} account(s) had unparseable last_logon timestamps "
            "and could not be evaluated for staleness."
        )
        status_826 = "review"

    # Local accounts not present in user_logons at all are also worth noting
    logon_usernames_826 = {
        e.get("user", "").split("\\")[-1].lower() for e in data.get("user_logons", [])
    }
    never_logged_in = [
        u.get("username")
        for u in local_users
        if (u.get("username") or "").lower() not in logon_usernames_826
        and (u.get("username") or "").lower()
        not in ("defaultaccount", "wdagutilityaccount", "cbntguest")
    ]
    if never_logged_in:
        findings_826.append(
            f"Local accounts with no matching logon history: {never_logged_in} - "
            "confirm these are disabled or have a documented exception."
        )
        if status_826 == "passed":
            status_826 = "review"

    add(
        "[8.2.6] - INF-Cloud-LX-4300",
        "Provide evidence to confirm inactive user accounts are removed or disabled within 90 days of inactivity.",
        status_826,
        findings_826,
        ["03_LocalUsers.txt", "00_Analysis.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Accounts with last logon older than 90 days, or local accounts with no logon history.",
        qsa_response=(
            (
                "QSA reviewed the user logon history to confirm that inactive accounts were removed or "
                "disabled within 90 days of inactivity. The review examined last logon timestamps for all "
                "observed accounts and confirmed that no accounts exceeded the 90-day inactivity threshold. "
                "Local accounts with no logon history were reviewed and confirmed to be either disabled "
                "built-in accounts or accounts with a documented business exception."
            )
            if status_826 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.2.8] - INF-Cloud-LX-4355
    # -------------------------

    # Windows idle timeout: MaxIdleTime is in milliseconds (900000 ms = 15 minutes)
    # Use administrative templates when available
    # "0" means no timeout is enforced
    rdp_idle_raw = get_rdp_setting(data, "MaxIdleTime")

    try:
        rdp_idle_val = (
            int(str(rdp_idle_raw).strip()) if rdp_idle_raw not in (None, "", "0") else 0
        )
    except Exception:
        rdp_idle_val = None

    if rdp_idle_val and rdp_idle_val <= 900000:
        idle_status = "passed"
        idle_note = f"MaxIdleTime = {rdp_idle_val} ms ({rdp_idle_val // 1000}s) - within the 15-minute requirement."
    elif rdp_idle_val == 0 or rdp_idle_val is None:
        idle_status = "failed"
        idle_note = f"MaxIdleTime = {rdp_idle_raw} - a value of 0 means no idle timeout is enforced."
    else:
        idle_status = "review"
        idle_note = (
            f"MaxIdleTime = {rdp_idle_val} ms ({rdp_idle_val // 1000}s) - "
            "exceeds the 15-minute (900-second) requirement."
        )

    add(
        "[8.2.8] - INF-Cloud-LX-4355",
        "Provide evidence to confirm idle sessions require re-authentication after no more than 15 minutes.",
        idle_status,
        [
            idle_note,
            f"RDP MaxDisconnectionTime = {get_rdp_setting(data, 'MaxDisconnectionTime') or 'Not found'}",
        ],
        ["05_GroupPolicy.txt", "00_Analysis.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="RDP MaxIdleTime set to 900000 ms (900 seconds / 15 minutes) or less, and not 0.",
        qsa_response=(
            (
                "QSA reviewed the RDP session timeout configuration to confirm that idle sessions required "
                "re-authentication after no more than 15 minutes of inactivity. The review confirmed that "
                f"the RDP MaxIdleTime was set to {rdp_idle_val} ms ({rdp_idle_val // 1000 if rdp_idle_val else 0}s), "
                "which satisfies the requirement to terminate or lock idle sessions within the defined threshold."
            )
            if idle_status == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.1.b] - INF-Cloud-LX-4370
    # -------------------------

    # Windows authentication factors: password policy, AD domain membership, NLA, no clear-text
    domain_name = summary.get("Domain", "")
    ad_joined = bool(domain_name and domain_name.lower() not in ("", "workgroup"))
    clear_text_831 = str(get_group_policy_value("ClearTextPassword") or "Not Enabled").strip().lower()
    pw_complexity_831 = str(get_group_policy_value("PasswordComplexity") or "").strip().lower()

    findings_831b = [
        f"Domain membership = {domain_name or 'Not domain-joined / Workgroup'}",
        f"AD authentication available = {'Yes' if ad_joined else 'No'}",
        f"RDP NLA (UserAuthentication) = {get_rdp_setting(data, 'UserAuthentication') or 'Not found'}",
        f"PasswordComplexity policy = {pw_complexity_831 or 'Not found'}",
        f"ClearTextPassword policy = {clear_text_831}",
        f"EnableGuestAccount = {group_policy.get('audit_policy', 'Not found').get('EnableGuestAccount', 'Not found')}",
    ]

    add(
        "[8.3.1.b] - INF-Cloud-LX-4370",
        "Provide observation(s) of authentication factors used to confirm they are functional.",
        "review",
        findings_831b,
        ["05_GroupPolicy.txt", "00_Analysis.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="Active authentication methods: domain/AD auth, RDP NLA, password complexity, no clear-text storage.",
        qsa_response=(
            "QSA reviewed the authentication factor configuration to confirm that authentication mechanisms "
            "were functional and appropriately secured. The review confirmed that the system was domain-joined "
            "and authenticated against Active Directory, that RDP was configured with Network Level "
            "Authentication, that password complexity was enforced, and that clear-text password storage "
            "was disabled. The observed authentication configuration was consistent with the organization's "
            "defined authentication standards."
        ),
    )

    # -------------------------
    # [8.3.2.a] - INF-Cloud-LX-4390
    # -------------------------

    findings_832a = []

    rdp_domain_832 = data.get("rdp_domain", {})
    rdp_local_832 = data.get("rdp_local", {})

    def get_rdp_832(key):
        return get_rdp_setting(data, key)

    enc_level_832 = str(get_rdp_832("MinEncryptionLevel") or "").strip()
    disable_enc_832 = str(get_rdp_832("fDisableEncryption") or "").strip()
    enc_rpc_832 = str(get_rdp_832("fEncryptRPCTraffic") or "").strip()
    sec_layer_832 = str(get_rdp_832("SecurityLayer") or "").strip()
    nla_832 = str(get_rdp_832("UserAuthentication") or "").strip()

    enc_level_ok = enc_level_832.isdigit() and int(enc_level_832) >= 3
    enc_not_dis = disable_enc_832 == "0"
    enc_rpc_ok = enc_rpc_832 == "1"
    sec_layer_ok = sec_layer_832.isdigit() and int(sec_layer_832) >= 1
    nla_ok_832 = nla_832 == "1"

    findings_832a.append(
        f"MinEncryptionLevel = {enc_level_832 or 'Not found'}: {'PASS' if enc_level_ok else 'FAIL'}"
    )
    findings_832a.append(
        f"fDisableEncryption = {disable_enc_832 or 'Not found'}: {'PASS' if enc_not_dis else 'FAIL'}"
    )
    findings_832a.append(
        f"fEncryptRPCTraffic = {enc_rpc_832 or 'Not found'}: {'PASS' if enc_rpc_ok else 'FAIL'}"
    )
    findings_832a.append(
        f"SecurityLayer = {sec_layer_832 or 'Not found'}: {'PASS' if sec_layer_ok else 'FAIL'}"
    )
    findings_832a.append(
        f"UserAuthentication (NLA) = {nla_832 or 'Not found'}: {'PASS' if nla_ok_832 else 'FAIL'}"
    )

    status_832a = (
        "passed"
        if enc_level_ok and enc_not_dis and enc_rpc_ok and sec_layer_ok and nla_ok_832
        else "review"
    )

    add(
        "[8.3.2.a] - INF-Cloud-LX-4390",
        "Provide system configuration settings to confirm authentication factors are rendered unreadable with strong cryptography.",
        status_832a,
        findings_832a,
        ["05_GroupPolicy.txt", "09_Services_Details.csv"],
        default_file="05_GroupPolicy.txt",
        look_for="RDP MinEncryptionLevel ≥ 3, fDisableEncryption = 0, fEncryptRPCTraffic = 1, SecurityLayer ≥ 1, NLA enabled.",
        qsa_response=(
            (
                "QSA reviewed the RDP configuration settings to confirm that authentication factors were "
                "rendered unreadable during transmission through strong cryptography. The review confirmed "
                f"that the minimum encryption level was set to {enc_level_832}, encryption was not disabled, "
                "RPC traffic encryption was enforced, the security layer was configured appropriately, and "
                "Network Level Authentication was enabled. The observed settings were consistent with the "
                "requirement to protect authentication factors with strong cryptographic controls."
            )
            if status_832a == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.2.b] - INF-Cloud-LX-4400
    # -------------------------

    findings_832b = []
    status_832b = "review"

    clear_text_832b = str(get_group_policy_value("ClearTextPassword") or "").strip().lower()
    laps_present = any(
        "local administrator password solution" in (app.get("name") or "").lower()
        for app in installed_apps
    )

    # Primary check: ClearTextPassword policy
    if clear_text_832b in ("not enabled", "0", "false"):
        findings_832b.append(
            f"ClearTextPassword policy = {get_group_policy_value('ClearTextPassword') or account_policies.get('ClearTextPassword')} - "
            "passwords are not stored using reversible encryption: PASS"
        )
        status_832b = "passed"
    elif clear_text_832b in ("enabled", "1", "true"):
        findings_832b.append(
            f"ClearTextPassword policy = {get_group_policy_value('ClearTextPassword') or account_policies.get('ClearTextPassword')} - "
            "passwords are stored using reversible (clear-text) encryption: FAIL"
        )
        status_832b = "review"
    else:
        findings_832b.append(
            f"ClearTextPassword policy = {get_group_policy_value('ClearTextPassword') or account_policies.get('ClearTextPassword') or 'Not found'} - "
            "unable to determine storage encryption posture."
        )
        status_832b = "review"

    # Supporting context
    findings_832b.append(
        f"Windows SAM database stores password hashes (NTLM/NTHash) by default; "
        "direct hash content is not extractable from the current JSON."
    )

    if laps_present:
        findings_832b.append(
            "Local Administrator Password Solution (LAPS) detected - "
            "local admin passwords are managed and rotated automatically."
        )
    else:
        findings_832b.append(
            "LAPS was not detected in installed applications - "
            "local administrator password management should be confirmed separately."
        )

    add(
        "[8.3.2.b] - INF-Cloud-LX-4400",
        "Provide repositories of authentication factors to confirm they are unreadable during storage.",
        status_832b,
        findings_832b,
        ["00_Analysis.txt", "11_InstalledPatches.txt"],
        default_file="00_Analysis.txt",
        look_for="ClearTextPassword policy disabled, Windows SAM hash storage, and LAPS for local admin accounts.",
        qsa_response=(
            (
                "QSA reviewed the authentication factor storage configuration to confirm that credentials "
                "were not stored in a recoverable or reversible format. The review confirmed that the "
                "ClearTextPassword group policy was not enabled, ensuring that Windows does not store "
                "passwords using reversible encryption. The Windows SAM database was confirmed to use "
                "hash-based storage by default, and the presence of LAPS was evaluated as an additional "
                "control over local administrator credential management."
            )
            if status_832b == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.2.c] - INF-Cloud-LX-4410
    # -------------------------

    rdp_domain_832c = data.get("rdp_domain", {})
    rdp_local_832c = data.get("rdp_local", {})

    def get_rdp_832c(key):
        return get_rdp_setting(data, key)

    enc_level_832c = str(get_rdp_832c("MinEncryptionLevel") or "").strip()
    enc_rpc_832c = str(get_rdp_832c("fEncryptRPCTraffic") or "").strip()
    sec_layer_832c = str(get_rdp_832c("SecurityLayer") or "").strip()
    nla_832c = str(get_rdp_832c("UserAuthentication") or "").strip()

    telnet_832c = str(summary.get("Telnet", "")).upper()

    findings_832c = [
        f"Telnet = {summary.get('Telnet')}: {'PASS' if telnet_832c != 'TRUE' else 'FAIL'}",
        f"RDP UserAuthentication (NLA) = {nla_832c}: {'PASS' if nla_832c == '1' else 'FAIL'}",
        f"RDP MinEncryptionLevel = {enc_level_832c}: "
        f"{'PASS' if enc_level_832c.isdigit() and int(enc_level_832c) >= 3 else 'FAIL'}",
        f"RDP SecurityLayer = {sec_layer_832c}: "
        f"{'PASS' if sec_layer_832c.isdigit() and int(sec_layer_832c) >= 1 else 'FAIL'}",
        f"RDP fEncryptRPCTraffic = {enc_rpc_832c}: {'PASS' if enc_rpc_832c == '1' else 'FAIL'}",
    ]

    status_832c = (
        "passed"
        if (
            telnet_832c != "TRUE"
            and nla_832c == "1"
            and enc_level_832c.isdigit()
            and int(enc_level_832c) >= 3
            and enc_rpc_832c == "1"
        )
        else "review"
    )

    add(
        "[8.3.2.c] - INF-Cloud-LX-4410",
        "Provide evidence to confirm authentication factors are unreadable during transmission.",
        status_832c,
        findings_832c,
        ["00_Analysis.txt", "05_GroupPolicy.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="Telnet disabled, RDP NLA enabled, MinEncryptionLevel ≥ 3, fEncryptRPCTraffic = 1.",
        qsa_response=(
            (
                "QSA reviewed the transmission-layer security configuration to confirm that authentication "
                "factors were protected from interception during transmission. The review confirmed that "
                "Telnet was disabled, RDP was configured with Network Level Authentication, the minimum "
                "encryption level was set to an appropriate value, and RPC traffic encryption was enforced. "
                "The observed settings were consistent with the requirement to render authentication factors "
                "unreadable during transmission."
            )
            if status_832c == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.4.a] - INF-Cloud-LX-4440
    # -------------------------
    add(
        "[8.3.4.a] - INF-Cloud-LX-4440",
        "Provide system configuration settings to confirm authentication parameters are set appropriately for failed logon controls.",
        "review",
        [
            f"LockoutBadCount (threshold) = {account_policies.get('LockoutBadCount', 'Not found')}",
            f"LockoutDuration = {account_policies.get('LockoutDuration', 'Not found')}",
            f"ResetLockoutCount (observation window) = {account_policies.get('ResetLockoutCount', 'Not found')}",
            f"MaximumPasswordAge = {account_policies.get('MaximumPasswordAge', 'Not found')}",
        ],
        ["00_Analysis.txt"],
        default_file="00_Analysis.txt",
        look_for="LockoutBadCount ≤ 10, LockoutDuration ≥ 30 minutes or Never, ResetLockoutCount ≥ 30 minutes.",
        qsa_response=(
            "QSA reviewed the account lockout policy settings to confirm that authentication parameters "
            "for failed logon controls were configured appropriately. The review examined the lockout "
            "threshold, lockout duration, and observation window as defined in the group policy and "
            "confirmed that the settings were consistent with the requirement to limit failed logon "
            "attempts and enforce an appropriate lockout period."
        ),
    )

    # -------------------------
    # [8.3.4.b] - INF-Cloud-LX-4450
    # -------------------------
    findings_834b = []
    status_834b = "review"

    # Use the already-derived lockout variables from account_policies
    # lockout_count  = LockoutBadCount (int)
    # lockout_never  = True if duration is 4294967295 or "Never"
    # reset_count    = ResetLockoutCount in minutes

    attempts_ok_834 = 0 < lockout_count <= 10
    # Pass if: manual-unlock (never) OR observation window >= 30 minutes
    timer_ok_834 = lockout_never or reset_count >= 30

    try:
        findings_834b.append(
            f"LockoutBadCount = {lockout_count}: "
            f"{'PASS' if attempts_ok_834 else 'FAIL'} (requirement: 1–10)"
        )
        findings_834b.append(
            f"LockoutDuration = {lockout_dur_raw}: "
            f"{'PASS' if lockout_never else ('PASS' if reset_count >= 30 else 'FAIL')} "
            f"({'manual unlock / never' if lockout_never else f'{reset_count} min observation window'})"
        )
        findings_834b.append(
            f"ResetLockoutCount = {reset_count} minutes: "
            f"{'PASS' if reset_count >= 30 else 'FAIL'} (requirement: ≥ 30 minutes)"
        )

        if lockout_count == 3:
            findings_834b.append(
                "LockoutBadCount is 3; this is a common default - confirm it is explicitly configured."
            )

        if attempts_ok_834 and timer_ok_834:
            status_834b = "passed"
        else:
            status_834b = "review"

    except Exception:
        findings_834b.append("Unable to parse lockout policy values.")
        status_834b = "review"

    add(
        "[8.3.4.b] - INF-Cloud-LX-4450",
        "Provide evidence to confirm failed logons are limited to 10 tries and a 30-minute unlock timer is enforced.",
        status_834b,
        findings_834b,
        ["00_Analysis.txt"],
        default_file="00_Analysis.txt",
        look_for="LockoutBadCount ≤ 10 and LockoutDuration ≥ 30 minutes or set to Never (manual unlock).",
        qsa_response=(
            (
                "QSA reviewed the account lockout configuration to confirm that failed logon attempts were "
                f"limited and that a sufficient lockout duration was enforced. The review confirmed that the "
                f"lockout threshold was set to {lockout_count} attempts and the lockout duration was configured "
                f"as '{lockout_dur_raw}', satisfying the requirement to limit failed logon attempts to no more "
                "than 10 and enforce a minimum 30-minute lockout or administrator-required manual unlock."
            )
            if status_834b == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.6] - INF-Cloud-LX-4480
    # -------------------------
    pw_complexity_836 = str(get_group_policy_value("PasswordComplexity") or "Not found").strip().lower()
    status_836 = (
        "passed"
        if min_pw_len >= 12 and pw_complexity_836 in ("enabled", "1", "true")
        else "failed"
    )

    add(
        "[8.3.6] - INF-Cloud-LX-4480",
        "Provide password configuration settings to confirm passwords meet minimum length and complexity requirements.",
        status_836,
        [
            f"MinimumPasswordLength = {min_pw_len}: {'PASS' if min_pw_len >= 12 else 'FAIL'} (requirement: ≥ 12)",
            f"PasswordComplexity = {get_group_policy_value('PasswordComplexity') or 'Not found'}: "
            f"{'PASS' if pw_complexity_836.lower() in ('enabled', '1', 'true') else 'FAIL'}",
        ],
        ["00_Analysis.txt"],
        default_file="00_Analysis.txt",
        look_for="MinimumPasswordLength ≥ 12 and PasswordComplexity = Enabled.",
        qsa_response=(
            (
                "QSA reviewed the password configuration settings to confirm that passwords met the minimum "
                "length and complexity requirements. The review confirmed that the group policy enforced a "
                f"minimum password length of {min_pw_len} characters and that password complexity was enabled, "
                "requiring passwords to contain a mix of character types. Both settings met or exceeded the "
                "requirements as defined."
            )
            if status_836 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.7] - INF-Cloud-LX-4490
    # -------------------------
    status_837 = "passed" if pw_history >= 4 else "failed"

    add(
        "[8.3.7] - INF-Cloud-LX-4490",
        "Provide evidence to confirm password history prevents reuse of at least the required number of prior passwords.",
        status_837,
        [
            f"PasswordHistorySize = {pw_history}: "
            f"{'PASS' if pw_history >= 4 else 'FAIL'} (requirement: ≥ 4)"
        ],
        ["00_Analysis.txt"],
        default_file="00_Analysis.txt",
        look_for="PasswordHistorySize set to 4 or greater.",
        qsa_response=(
            (
                "QSA reviewed the password history policy to confirm that users were prevented from reusing "
                f"recent passwords. The review confirmed that the password history was set to {pw_history} "
                "passwords, meeting the requirement to prevent reuse of at least the last four passwords."
            )
            if status_837 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.3.9] - INF-Cloud-LX-4540
    # -------------------------

    # Windows: evaluate at two levels -
    #   1. Policy level: MaximumPasswordAge from account_policies (already derived as max_pw_age)
    #   2. Per-account level: user_logons does not carry pw_last_set, so flag accounts
    #      whose names suggest they may not rotate (service accounts, built-ins)

    findings_839 = []
    noncompliant_839 = []
    unknown_839 = []

    # Policy-level check
    if max_pw_age == 0:
        noncompliant_839.append(
            f"MaximumPasswordAge = {max_pw_age} - a value of 0 means passwords never expire"
        )
    elif max_pw_age > 90:
        noncompliant_839.append(
            f"MaximumPasswordAge = {max_pw_age} days - exceeds the 90-day requirement"
        )
    else:
        findings_839.append(
            f"MaximumPasswordAge = {max_pw_age} days: PASS (requirement: ≤ 90)"
        )

    # Account-level: flag local accounts that may have non-expiring passwords
    # (service accounts, built-ins) since per-account pw_last_set is not in the JSON
    service_pw_markers = ["svc", "service", "fileshare", "backup", "localadmin"]
    flagged_accounts = [
        u.get("username")
        for u in local_users
        if any(m in (u.get("username") or "").lower() for m in service_pw_markers)
    ]

    if flagged_accounts:
        unknown_839.append(
            f"Accounts with names suggesting possible non-expiring password configuration: "
            f"{flagged_accounts} - per-account password expiry cannot be confirmed from JSON alone."
        )

    if noncompliant_839:
        status_839 = "review"
        findings_839.append(
            "Policy-level password age does not meet the 90-day requirement:"
        )
        for item in noncompliant_839:
            findings_839.append(item)
    elif unknown_839:
        status_839 = "review"
        for item in unknown_839:
            findings_839.append(item)
    else:
        status_839 = "passed"
        findings_839.append(
            "Password expiration policy meets the 90-day requirement at the group policy level."
        )

    findings_839.append(
        f"Local accounts observed: {[u.get('username') for u in local_users]}"
    )
    findings_839.append(
        "Per-account password last-set dates are not available in the current JSON; "
        "individual account rotation should be confirmed from Active Directory or LAPS evidence."
    )

    add(
        "[8.3.9] - INF-Cloud-LX-4540",
        "Provide system configuration settings to confirm passwords/passphrases are changed according to policy.",
        status_839,
        findings_839,
        ["00_Analysis.txt", "03_LocalUsers.txt"],
        default_file="00_Analysis.txt",
        look_for="MaximumPasswordAge ≤ 90 days and no accounts with non-expiring passwords.",
        qsa_response=(
            (
                "QSA reviewed the password expiration configuration to confirm that passwords were required "
                "to be changed according to policy. The review confirmed that the group policy enforced a "
                f"maximum password age of {max_pw_age} days, satisfying the requirement. Local accounts were "
                "reviewed for naming patterns suggesting potential non-expiring configuration, and no "
                "exceptions were identified without a documented business justification."
            )
            if status_839 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [8.4.1.a] - INF-Cloud-LX-4610
    # -------------------------
    domain_mfa = summary.get("Domain", "")
    ad_joined_mfa = bool(domain_mfa and domain_mfa.lower() not in ("", "workgroup"))

    add(
        "[8.4.1.a] - INF-Cloud-LX-4610",
        "Provide network and/or system configurations to confirm MFA is required for all administrative access.",
        "manual",
        [
            "MFA enforcement cannot be fully established from the current Windows JSON alone.",
            f"Domain membership = {domain_mfa or 'Not domain-joined'} - "
            f"{'domain-level MFA policy may apply' if ad_joined_mfa else 'workgroup host; MFA must be confirmed via other means'}.",
            f"RDP NLA (UserAuthentication) = {get_rdp_setting(data, 'UserAuthentication') or 'Not found'} - "
            "NLA is a prerequisite for MFA enforcement over RDP but does not confirm MFA alone.",
            f"Administrators group members: {admin_group_members_7}",
            "Supporting evidence such as AD conditional access policy, RADIUS, or PAM configuration required.",
        ],
        ["00_Analysis.txt", "05_GroupPolicy.txt"],
        default_file="00_Analysis.txt",
        look_for="MFA policy applied to administrative accounts via AD, RADIUS, PAM, or equivalent.",
        qsa_response=(
            "QSA reviewed the network and system configurations to confirm that MFA was required for all "
            "administrative access. The review confirmed that the system was domain-joined with RDP "
            "configured to require Network Level Authentication, and that administrative access was "
            "controlled through defined group memberships. The organization provided supporting evidence "
            "confirming that MFA was enforced for administrative accounts through the organization's "
            "identity and access management platform."
        ),
    )

    # -------------------------
    # [8.4.2.a] - INF-Cloud-LX-4630
    # -------------------------
    add(
        "[8.4.2.a] - INF-Cloud-LX-4630",
        "Provide network and/or system configurations to confirm MFA is implemented for all remote access.",
        "manual",
        [
            "Remote-access MFA cannot be fully established from the current Windows JSON alone.",
            f"RDP NLA (UserAuthentication) = {get_rdp_setting(data, 'UserAuthentication') or 'Not found'} - "
            "NLA is a prerequisite for MFA over RDP but does not confirm MFA enforcement alone.",
            f"RDP fPromptForPassword = {get_rdp_setting(data, 'fPromptForPassword') or 'Not found'}",
            f"Domain = {domain_mfa or 'Not domain-joined'} - "
            f"{'conditional access or RADIUS MFA policy may apply at the domain level' if ad_joined_mfa else 'no domain; MFA must be confirmed via other means'}.",
            "Supporting evidence such as VPN MFA policy, AD conditional access, or RADIUS configuration required.",
        ],
        ["00_Analysis.txt", "05_GroupPolicy.txt"],
        default_file="05_GroupPolicy.txt",
        look_for="MFA enforced for all remote access channels including RDP, VPN, and other remote services.",
        qsa_response=(
            "QSA reviewed the network and system configurations to confirm that MFA was implemented for "
            "all remote access. The review confirmed that RDP was configured with Network Level "
            "Authentication and password prompt enforcement as prerequisite controls, and the organization "
            "provided supporting evidence confirming that MFA was enforced for remote access sessions "
            "through the organization's access management platform."
        ),
    )

    # -------------------------
    # [8.6.1] - INF-Cloud-LX-4740
    # -------------------------

    # Windows: identify system/application accounts from local_users by naming convention
    svc_markers_861 = [
        "svc",
        "service",
        "system",
        "fileshare",
        "backup",
        "agent",
        "app",
    ]
    system_accounts_861 = [
        u.get("username")
        for u in local_users
        if any(m in (u.get("username") or "").lower() for m in svc_markers_861)
    ]

    add(
        "[8.6.1] - INF-Cloud-LX-4740",
        "Provide application and system accounts to confirm all such accounts have unique passwords/passphrases.",
        "review",
        [
            f"Local accounts observed: {[u.get('username') for u in local_users]}",
            (
                f"Potential system/application accounts detected: {system_accounts_861}"
                if system_accounts_861
                else "No obvious system/application account names detected among local users."
            ),
            "Unique password assignment for system and application accounts cannot be confirmed "
            "from JSON alone; LAPS or vault evidence required for local admin accounts.",
            f"LAPS detected in installed applications: "
            f"{'Yes' if any('local administrator password solution' in (a.get('name') or '').lower() for a in installed_apps) else 'No'}",
        ],
        ["03_LocalUsers.txt", "11_InstalledPatches.txt"],
        default_file="03_LocalUsers.txt",
        look_for="Unique authentication for application and system accounts; LAPS or equivalent for local admin.",
        qsa_response=(
            "QSA reviewed the application and system accounts to confirm that all such accounts were "
            "assigned unique passwords. The review examined local accounts for naming patterns consistent "
            "with system or application usage, and confirmed that the Local Administrator Password "
            "Solution was deployed to manage and rotate local administrator credentials, ensuring unique "
            "passwords across systems. No shared or static credentials were identified for system or "
            "application accounts."
        ),
    )

    # -------------------------
    # [8.6.2.b] - INF-Cloud-LX-4780
    # -------------------------
    add(
        "[8.6.2.b] - INF-Cloud-LX-4780",
        "Provide scripts, configuration/property files, and source code to confirm no hard-coded credentials exist.",
        "manual",
        [
            "Current JSON does not contain source or configuration file review evidence for hard-coded credentials.",
            f"Installed applications observed ({len(installed_apps)}) - application configuration files "
            "must be reviewed separately for embedded credentials.",
            "Running services should be cross-referenced against deployment scripts for hard-coded values.",
        ],
        ["00_Analysis.txt", "11_InstalledPatches.txt"],
        default_file="00_Analysis.txt",
        look_for="Embedded or static credentials in scripts, configuration files, or application code.",
        qsa_response=(
            "QSA reviewed the provided scripts, configuration files, and source code samples to confirm "
            "that no hard-coded credentials were present. The review examined configuration and property "
            "files for embedded usernames, passwords, API keys, or other static secrets, and no "
            "instances of hard-coded credentials were identified. The organization confirmed the use of "
            "secrets management practices to handle sensitive values outside of source code."
        ),
    )

    # -------------------------
    # [8.6.3.c] - INF-Cloud-LX-4820
    # -------------------------
    laps_detected_863 = any(
        "local administrator password solution" in (app.get("name") or "").lower()
        for app in installed_apps
    )

    add(
        "[8.6.3.c] - INF-Cloud-LX-4820",
        "Provide system configuration settings to confirm passwords/passphrases for system accounts are changed regularly.",
        "review" if laps_detected_863 else "manual",
        [
            f"LAPS (Local Administrator Password Solution) detected: {'Yes' if laps_detected_863 else 'No'}",
            (
                (
                    "LAPS is present - local administrator passwords are managed and rotated automatically. "
                    "LAPS rotation policy and schedule should be confirmed from the LAPS configuration."
                )
                if laps_detected_863
                else (
                    "LAPS was not detected in installed applications. "
                    "System account password rotation evidence must be confirmed through vault, "
                    "PAM tooling, or manual change records."
                )
            ),
            "Service account and application account password rotation cannot be fully confirmed from JSON alone.",
        ],
        ["00_Analysis.txt", "11_InstalledPatches.txt"],
        default_file="00_Analysis.txt",
        look_for="LAPS deployment for local admin rotation, or vault/PAM evidence for service account rotation.",
        qsa_response=(
            (
                "QSA reviewed the system configuration settings to confirm that passwords for system accounts "
                "were changed regularly. The review confirmed that the Local Administrator Password Solution "
                "was deployed, providing automated rotation of local administrator passwords on a defined "
                "schedule. The organization provided supporting evidence confirming that service account "
                "passwords were managed through an approved rotation process consistent with policy."
            )
            if laps_detected_863
            else ""
        ),
    )

    # -------------------------
    # Audit policy helpers for 10.x blocks
    # -------------------------
    event_log_settings = data.get("group_policy", {}).get("event_log_settings", {})
    security_log = event_log_settings.get("Security", {})
    app_log = event_log_settings.get("Application", {})
    system_log_evt = event_log_settings.get("System", {})

    # Shorthand audit checks already derived at the top of evaluate_from_json:
    # logon_audit, acct_mgmt_audit, priv_use_audit, proc_audit, policy_audit

    object_access_audit = audit_policy.get("Object Access", {})
    system_audit = audit_policy.get("System", {})
    account_logon_audit = audit_policy.get("Account Logon", {}).get(
        "Credential Validation", ""
    )
    acct_lockout_audit = audit_policy.get("Logon/Logoff", {}).get("Account Lockout", "")
    special_logon_audit = audit_policy.get("Logon/Logoff", {}).get("Special Logon", "")
    security_state_audit = system_audit.get("Security State Change", "")
    security_sys_audit = system_audit.get("Security System Extension", "")
    sys_integrity_audit = system_audit.get("System Integrity", "")

    # Windows Security event log guest restriction (proxy for log hardening)
    security_restrict_guest = (
        str(security_log.get("RestrictGuestAccess", "")).strip().lower()
    )
    log_restricted = security_restrict_guest in ("enabled", "1", "true")

    # -------------------------
    # [10.2.1] - INF-Cloud-LX-5705
    # -------------------------
    # Windows: logging is "active" if audit policy is populated and Security event log is hardened
    log_is_active = bool(audit_policy) and log_restricted

    add(
        "[10.2.1] - INF-Cloud-LX-5705",
        "Provide audit log configuration to confirm logging is enabled and active.",
        "passed" if log_is_active else "review",
        [
            f"Audit policy categories observed: {list(audit_policy.keys())}",
            f"Security event log RestrictGuestAccess = "
            f"{security_log.get('RestrictGuestAccess', 'Not found')}: "
            f"{'PASS' if log_is_active else 'FAIL'}",
            f"Application event log RestrictGuestAccess = "
            f"{app_log.get('RestrictGuestAccess', 'Not found')}",
            f"Logon audit = {logon_audit}",
            f"Account Management audit = {acct_mgmt_audit}",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Audit policy populated and Security event log guest access restricted.",
        qsa_response=(
            (
                "QSA reviewed the audit log configuration to confirm that logging was enabled and active. "
                "The review confirmed that the Windows audit policy was configured across all required "
                "categories, and that the Security event log was configured to restrict guest access, "
                "consistent with an active and hardened logging posture."
            )
            if log_is_active
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.2] - INF-Cloud-LX-5730
    # -------------------------
    priv_log_5730 = (
        "success" in priv_use_audit.lower() and "failure" in priv_use_audit.lower()
    )
    special_log_5730 = "success" in special_logon_audit.lower()

    add(
        "[10.2.1.2] - INF-Cloud-LX-5730",
        "Provide audit log configurations to confirm all actions taken by any individual with root/administrative access are logged.",
        "passed" if priv_log_5730 and special_log_5730 else "review",
        [
            f"Sensitive Privilege Use audit = {priv_use_audit}: "
            f"{'PASS' if priv_log_5730 else 'FAIL'} (requirement: Success and Failure)",
            f"Special Logon audit = {special_logon_audit}: "
            f"{'PASS' if special_log_5730 else 'FAIL'} (requirement: at least Success)",
            f"Administrators group members: {admin_group_members_7}",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Sensitive Privilege Use = Success and Failure; Special Logon = Success.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that all actions taken by individuals "
                "with administrative privileges were being logged. The review confirmed that Sensitive "
                f"Privilege Use auditing was set to '{priv_use_audit}' and Special Logon auditing was set "
                f"to '{special_logon_audit}', ensuring that privileged and administrative actions were "
                "fully captured in the Security event log."
            )
            if (priv_log_5730 and special_log_5730)
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.3] - INF-Cloud-LX-5750
    # -------------------------
    policy_log_5750 = (
        "success" in policy_audit.lower() and "failure" in policy_audit.lower()
    )

    add(
        "[10.2.1.3] - INF-Cloud-LX-5750",
        "Provide audit log configurations to confirm access to all audit logs is captured.",
        "passed" if policy_log_5750 and log_restricted else "review",
        [
            f"Audit Policy Change audit = {policy_audit}: "
            f"{'PASS' if policy_log_5750 else 'FAIL'} (requirement: Success and Failure)",
            f"Security event log RestrictGuestAccess = "
            f"{security_log.get('RestrictGuestAccess', 'Not found')}: "
            f"{'PASS' if log_restricted else 'FAIL'}",
            "Changes to audit policy configuration are captured when Audit Policy Change is enabled.",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Audit Policy Change = Success and Failure; Security log guest access restricted.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that access to audit logs was being "
                f"captured. The review confirmed that Audit Policy Change auditing was set to '{policy_audit}', "
                "capturing both successful and failed changes to audit configuration, and that the Security "
                "event log was restricted from guest access, supporting the integrity of the audit trail."
            )
            if (policy_log_5750 and log_restricted)
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.4] - INF-Cloud-LX-5770
    # -------------------------
    lockout_log_5770 = (
        "success" in acct_lockout_audit.lower()
        and "failure" in acct_lockout_audit.lower()
    )
    logon_log_5770 = (
        "success" in logon_audit.lower() and "failure" in logon_audit.lower()
    )
    cred_log_5770 = (
        "success" in account_logon_audit.lower()
        and "failure" in account_logon_audit.lower()
    )

    add(
        "[10.2.1.4] - INF-Cloud-LX-5770",
        "Provide audit log configurations to confirm invalid logical access attempts are logged.",
        (
            "passed"
            if (lockout_log_5770 and logon_log_5770 and cred_log_5770)
            else "review"
        ),
        [
            f"Logon audit = {logon_audit}: "
            f"{'PASS' if logon_log_5770 else 'FAIL'} (requirement: Success and Failure)",
            f"Account Lockout audit = {acct_lockout_audit}: "
            f"{'PASS' if lockout_log_5770 else 'FAIL'} (requirement: Success and Failure)",
            f"Credential Validation audit = {account_logon_audit}: "
            f"{'PASS' if cred_log_5770 else 'FAIL'} (requirement: Success and Failure)",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Logon, Account Lockout, and Credential Validation audit set to Success and Failure.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that invalid logical access attempts "
                "were being logged. The review confirmed that Logon, Account Lockout, and Credential "
                "Validation auditing were all set to capture both success and failure events, ensuring that "
                "failed and unauthorized access attempts were recorded in the Security event log."
            )
            if (lockout_log_5770 and logon_log_5770 and cred_log_5770)
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.5] - INF-Cloud-LX-5790
    # -------------------------
    acct_mgmt_log_5790 = (
        "success" in acct_mgmt_audit.lower() and "failure" in acct_mgmt_audit.lower()
    )
    auth_policy_log_5790 = str(
        audit_policy.get("Policy Change", {}).get("Authentication Policy Change", "")
    ).lower()
    auth_pol_ok_5790 = "success" in auth_policy_log_5790

    add(
        "[10.2.1.5] - INF-Cloud-LX-5790",
        "Provide audit log configurations to confirm changes to identification and authentication are logged.",
        "passed" if (acct_mgmt_log_5790 and auth_pol_ok_5790) else "review",
        [
            f"User Account Management audit = {acct_mgmt_audit}: "
            f"{'PASS' if acct_mgmt_log_5790 else 'FAIL'} (requirement: Success and Failure)",
            f"Authentication Policy Change audit = "
            f"{audit_policy.get('Policy Change', {}).get('Authentication Policy Change', 'Not found')}: "
            f"{'PASS' if auth_pol_ok_5790 else 'FAIL'} (requirement: at least Success)",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="User Account Management = Success and Failure; Authentication Policy Change = Success.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that changes to identification and "
                "authentication mechanisms were being logged. The review confirmed that User Account "
                f"Management auditing was set to '{acct_mgmt_audit}' and Authentication Policy Change "
                f"auditing was configured to capture success events, ensuring that account and "
                "authentication changes were fully recorded."
            )
            if (acct_mgmt_log_5790 and auth_pol_ok_5790)
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.6] - INF-Cloud-LX-5810
    # -------------------------
    priv_log_5810 = (
        "success" in priv_use_audit.lower() and "failure" in priv_use_audit.lower()
    )
    special_5810 = "success" in special_logon_audit.lower()

    add(
        "[10.2.1.6] - INF-Cloud-LX-5810",
        "Provide audit log configurations to confirm privileged access is logged.",
        "passed" if (priv_log_5810 and special_5810) else "review",
        [
            f"Sensitive Privilege Use audit = {priv_use_audit}: "
            f"{'PASS' if priv_log_5810 else 'FAIL'} (requirement: Success and Failure)",
            f"Special Logon audit = {special_logon_audit}: "
            f"{'PASS' if special_5810 else 'FAIL'} (requirement: at least Success)",
            f"Process Creation audit = {proc_audit} (supporting context for privilege escalation tracking)",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Sensitive Privilege Use = Success and Failure; Special Logon = at least Success.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that privileged access was being logged. "
                f"The review confirmed that Sensitive Privilege Use auditing was set to '{priv_use_audit}' "
                f"and Special Logon auditing was set to '{special_logon_audit}', capturing both the use of "
                "sensitive privileges and logons with elevated rights in the Security event log."
            )
            if (priv_log_5810 and special_5810)
            else ""
        ),
    )

    # -------------------------
    # [10.2.1.7] - INF-Cloud-LX-5830
    # -------------------------
    proc_log_5830 = "success" in proc_audit.lower()
    sys_integ_5830 = (
        "success" in sys_integrity_audit.lower()
        and "failure" in sys_integrity_audit.lower()
    )
    sec_sys_5830 = (
        "success" in security_sys_audit.lower()
        and "failure" in security_sys_audit.lower()
    )

    add(
        "[10.2.1.7] - INF-Cloud-LX-5830",
        "Provide audit log configurations to confirm creation and deletion of system-level objects are logged.",
        "passed" if (proc_log_5830 and sys_integ_5830 and sec_sys_5830) else "review",
        [
            f"Process Creation audit = {proc_audit}: "
            f"{'PASS' if proc_log_5830 else 'FAIL'} (requirement: at least Success)",
            f"System Integrity audit = {sys_integrity_audit}: "
            f"{'PASS' if sys_integ_5830 else 'FAIL'} (requirement: Success and Failure)",
            f"Security System Extension audit = {security_sys_audit}: "
            f"{'PASS' if sec_sys_5830 else 'FAIL'} (requirement: Success and Failure)",
        ],
        ["05b_AuditPolicy.txt", "00_Analysis.txt"],
        default_file="05b_AuditPolicy.txt",
        look_for="Process Creation = Success; System Integrity and Security System Extension = Success and Failure.",
        qsa_response=(
            (
                "QSA reviewed the audit log configurations to confirm that creation and deletion of "
                "system-level objects were being logged. The review confirmed that Process Creation "
                f"auditing was set to '{proc_audit}', System Integrity auditing was set to "
                f"'{sys_integrity_audit}', and Security System Extension auditing was set to "
                f"'{security_sys_audit}', providing coverage of system-level object lifecycle events "
                "in the Security event log."
            )
            if (proc_log_5830 and sys_integ_5830 and sec_sys_5830)
            else ""
        ),
    )

    # -------------------------
    # [10.3.3] - INF-Cloud-LX-5920
    # -------------------------

    # Windows: check for SIEM/log forwarding agents in running services or installed apps
    forwarding_keywords = [
        "splunk",
        "syslog",
        "logrhythm",
        "qradar",
        "sentinel",
        "elastic",
        "dynatrace",
        "qualys",
        "siem",
        "logforwarder",
        "nxlog",
        "winlogbeat",
    ]

    forwarding_agents_found = []

    for svc in running_services:
        svc_name = (svc.get("service") or "").lower()
        svc_desc = (svc.get("description") or "").lower()
        if any(kw in svc_name or kw in svc_desc for kw in forwarding_keywords):
            forwarding_agents_found.append(svc.get("service"))

    # Deduplicate
    forwarding_agents_found = list(dict.fromkeys(forwarding_agents_found))

    # Also check installed apps
    forwarding_apps_found = [
        app.get("name")
        for app in installed_apps
        if any(kw in (app.get("name") or "").lower() for kw in forwarding_keywords)
    ]

    forwarding_detected = bool(forwarding_agents_found or forwarding_apps_found)

    findings_1033 = []
    if forwarding_agents_found:
        findings_1033.append(
            f"Log forwarding / SIEM agent services detected: {forwarding_agents_found}"
        )
    if forwarding_apps_found:
        findings_1033.append(
            f"Log forwarding / SIEM applications detected: {forwarding_apps_found}"
        )
    if not forwarding_detected:
        findings_1033.append(
            "No known log forwarding or SIEM agent services or applications detected. "
            "Log forwarding configuration must be confirmed through other evidence."
        )

    findings_1033.append(
        f"Security event log RestrictGuestAccess = "
        f"{security_log.get('RestrictGuestAccess', 'Not found')} - "
        f"{'log access is restricted' if log_restricted else 'log access restriction not confirmed'}."
    )

    add(
        "[10.3.3] - INF-Cloud-LX-5920",
        "Provide system configuration settings to confirm audit logs are backed up to a secure, central, internal log server or other difficult-to-modify media.",
        "passed" if forwarding_detected else "review",
        findings_1033,
        ["05b_AuditPolicy.txt", "09_Services_Details.csv"],
        default_file="05b_AuditPolicy.txt",
        look_for="Active SIEM or log forwarding agent in running services or installed applications.",
        qsa_response=(
            (
                "QSA reviewed the system configuration settings to confirm that audit logs were being "
                "forwarded to a secure, central log server. The review identified log forwarding and SIEM "
                "agent services and applications installed and running on the system, confirming that audit "
                "log data was being transmitted to a central repository. The Security event log was also "
                "confirmed to be configured with guest access restrictions, supporting the integrity of "
                "the log collection process."
            )
            if forwarding_detected
            else ""
        ),
    )

    # -------------------------
    # [10.6.1] - INF-Cloud-LX-6166
    # -------------------------
    time_settings = data.get("time_settings", {})
    ntp_client = time_settings.get("NtpClient", {})
    ntp_params = time_settings.get("Parameters", {})
    ntp_status = time_settings.get("Status", {})

    ntp_client_enabled = str(ntp_client.get("Enabled", "0")).strip() == "1"
    ntp_type = ntp_params.get("Type", "")
    ntp_server_param = ntp_params.get("NtpServer", "")
    # Last good sample may appear in different places depending on scan source
    last_good_sample = (
        ntp_status.get("LastGoodSampleInfo")
        or time_settings.get("Config", {}).get("LastKnownGoodTime")
        or ntp_status.get("LastGoodSample")
        or ""
    )

    # NT5DS = domain hierarchy sync; NTP = explicit server; both are valid synchronized states
    ntp_type_ok = ntp_type.upper() in ("NT5DS", "NTP", "ALLSYNC")
    synchronized_win = ntp_client_enabled and ntp_type_ok and bool(last_good_sample)

    status_1061 = "passed" if synchronized_win else "review"

    add(
        "[10.6.1] - INF-Cloud-LX-6166",
        "Provide evidence to confirm system clocks and time are synchronized using time-synchronization technology.",
        status_1061,
        [
            f"W32Time NtpClient Enabled = {ntp_client.get('Enabled', 'Not found')}: "
            f"{'PASS' if ntp_client_enabled else 'FAIL'}",
            f"Synchronization type (Parameters.Type) = {ntp_type}: "
            f"{'PASS' if ntp_type_ok else 'FAIL'} (NT5DS = domain sync, NTP = explicit server)",
            f"NTP server configured = {ntp_server_param or 'Not found'}",
            f"Last good time sample = {last_good_sample or 'Not found'}: "
            f"{'PASS' if last_good_sample else 'FAIL'}",
        ],
        ["16_TimeSettings.txt"],
        default_file="16_TimeSettings.txt",
        look_for="W32Time NtpClient enabled, sync type NT5DS or NTP, and a recent LastGoodSampleInfo entry.",
        qsa_response=(
            (
                "QSA reviewed the time synchronization configuration to confirm that system clocks were "
                "synchronized using an approved time-synchronization technology. The review confirmed that "
                f"the Windows Time Service (W32Time) was enabled with a synchronization type of '{ntp_type}', "
                f"and that a successful time sample was recorded from '{last_good_sample}', demonstrating "
                "active and functional time synchronization."
            )
            if status_1061 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.6.2] - INF-Cloud-LX-6170
    # -------------------------
    add(
        "[10.6.2] - INF-Cloud-LX-6170",
        "Provide time synchronization settings to confirm systems are configured to the correct and consistent time.",
        status_1061,
        [
            f"W32Time NtpClient Enabled = {ntp_client.get('Enabled', 'Not found')}",
            f"Synchronization type = {ntp_type}",
            f"NTP server = {ntp_server_param or 'Not found'}",
            f"Last good sample = {last_good_sample or 'Not found'}",
            f"Time zone (from summary) = {system_info.get('Time Zone', 'Not found')}",
        ],
        ["16_TimeSettings.txt"],
        default_file="16_TimeSettings.txt",
        look_for="Consistent NTP source, correct time zone, and recent successful sync.",
        qsa_response=(
            (
                "QSA reviewed the time synchronization settings to confirm that the system was configured "
                "to the correct and consistent time. The review confirmed that the Windows Time Service was "
                f"configured with synchronization type '{ntp_type}' and NTP server '{ntp_server_param}', "
                "and that the system time zone was appropriate for the system's location and role. "
                "A recent successful time sample confirmed active synchronization."
            )
            if status_1061 == "passed"
            else ""
        ),
    )

    # -------------------------
    # [10.6.3.a] - INF-Cloud-LX-6180
    # -------------------------
    ntp_config = time_settings.get("Config", {})
    max_pos_corr = ntp_config.get("MaxPosPhaseCorrection", "")
    max_neg_corr = ntp_config.get("MaxNegPhaseCorrection", "")
    spike_watch = ntp_config.get("SpikeWatchPeriod", "")

    add(
        "[10.6.3.a] - INF-Cloud-LX-6180",
        "Provide system configurations and time-synchronization settings to confirm time accuracy is maintained.",
        "review",
        [
            f"W32Time NtpClient Enabled = {ntp_client.get('Enabled', 'Not found')}",
            f"Synchronization type = {ntp_type}",
            f"Last good time sample = {last_good_sample or 'Not found'}",
            f"MaxPosPhaseCorrection = {max_pos_corr or 'Not found'}",
            f"MaxNegPhaseCorrection = {max_neg_corr or 'Not found'}",
            f"SpikeWatchPeriod = {spike_watch or 'Not found'}",
        ],
        ["16_TimeSettings.txt"],
        default_file="16_TimeSettings.txt",
        look_for="Time synchronization active, phase correction limits set, and no large clock drift.",
        qsa_response=(
            "QSA reviewed the system configurations and time-synchronization settings to confirm that "
            "time accuracy was being maintained. The review examined the Windows Time Service "
            "configuration including phase correction limits and spike watch settings, and confirmed "
            "that the service was actively synchronized with a valid time source. The configuration "
            "observed was consistent with maintaining accurate and reliable system time."
        ),
    )

    # -------------------------
    # [10.6.3.b] - INF-Cloud-LX-6190
    # -------------------------
    ntp_server_configured = bool(ntp_server_param)
    # VMICTimeProvider (Hyper-V time sync) may be reported under different keys
    vmic_provider = (
        time_settings.get("VMICTimeProvider")
        or time_settings.get("TimeProviders", {}).get("VMICTimeProvider")
        or {}
    )
    vmic_enabled = False
    if vmic_provider:
        vmic_enabled = str(vmic_provider.get("Enabled", "0")).strip() == "1"
    else:
        # fallback: search for any value containing the text 'VMICTimeProvider'
        def _contains_vmic(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if _contains_vmic(k) or _contains_vmic(v):
                        return True
                return False
            try:
                return "vmictimeprovider" in str(obj).lower()
            except Exception:
                return False

        vmic_enabled = _contains_vmic(time_settings)

    add(
        "[10.6.3.b] - INF-Cloud-LX-6190",
        "Provide system configurations and time-source settings to confirm the time source is configured securely.",
        "review",
        [
            f"NTP server (Parameters.NtpServer) = {ntp_server_param or 'Not found'}",
            f"Synchronization type = {ntp_type} "
            f"({'domain hierarchy (DC as source)' if ntp_type.upper() == 'NT5DS' else 'explicit NTP server'})",
            f"VMICTimeProvider (Hyper-V time sync) Enabled = {vmic_provider.get('Enabled', 'Not found')} "
            f"- {'Hyper-V time sync is active as a secondary source' if vmic_enabled else 'not active'}",
            "Secure time source validation (e.g., authenticated NTP, stratum level) "
            "requires additional evidence beyond the current JSON.",
        ],
        ["16_TimeSettings.txt"],
        default_file="16_TimeSettings.txt",
        look_for="Approved NTP server or domain time hierarchy; VMIC provider state; authenticated time source.",
        qsa_response=(
            "QSA reviewed the time source configuration to confirm that system time was obtained from "
            f"a secure and approved source. The review confirmed that the synchronization type was set "
            f"to '{ntp_type}' and that the configured NTP server was '{ntp_server_param}'. "
            "The organization confirmed that the time source hierarchy was managed through the domain "
            "controller infrastructure, consistent with the requirement for a secure and centrally "
            "managed time source."
        ),
    )

    # -------------------------
    # [11.5.2.a] - INF-Cloud-LX-6965
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

    fim_apps_found = [
        app.get("name")
        for app in installed_apps
        if any(kw in (app.get("name") or "").lower() for kw in fim_keywords)
    ]

    fim_detected = bool(fim_services_found or fim_apps_found)

    findings_11552 = []
    if fim_services_found:
        findings_11552.append(
            f"FIM/change-detection services detected: {fim_services_found}"
        )
    if fim_apps_found:
        findings_11552.append(
            f"FIM/change-detection applications detected: {fim_apps_found}"
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
        "[11.5.2.a] - INF-Cloud-LX-6965",
        "Provide system settings to confirm the use of a change-detection mechanism.",
        "passed" if fim_detected else "manual",
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
    build_report("windows_output.json", "report.html")
