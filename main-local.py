# main-local.py
# Headless batch runner for the Zip Audit report builder.
# Uses the same parser and report modules as main.py, but runs without a GUI.

import os
import re
import json

from linuxParser import build_linux_output
from windowsParser import build_windows_output
import linuxReport
from linuxReport import load_key_vars_linux
import windowsReport
from windowsReport import load_key_vars_windows


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


# headless runner for automation and quick testing
def main():
    # This is a simple headless runner for automation or quick local testing.
    # Update sample_folders to match the folders you want to process.
    sample_folders = ["sampleWindows1", "sampleLinux1"]

    site_reports = []
    hosts_meta = []

    for folder in sample_folders:
        os_type = detect_os_type(folder)

        if os_type is None:
            print(
                f"WARNING: Could not detect OS type for folder '{folder}' - "
                "neither summary.csv nor 00_Analysis.txt found. Skipping."
            )
            continue

        temp_json_path = f"output_json/{folder}_temp_output.json"

        if os_type == "windows":
            # parse Windows host output and choose a consistent filename
            data = build_windows_output(folder, temp_json_path)
            key_vars = load_key_vars_windows(data)
            hostname = data.get("systeminfo", {}).get("Host Name") or "Unknown Host"
            slug = slugify(hostname)
            json_path = f"output_json/windows_output_{slug}.json"
            report_path = f"reports/report_{slug}.html"
            report_module = windowsReport

        else:
            # parse Linux host output and choose a consistent filename
            data = build_linux_output(folder, temp_json_path)
            key_vars = load_key_vars_linux(data)
            hostname = (
                data.get("summary", {}).get("Host")
                or data.get("uname", {}).get("host")
                or "Unknown Host"
            )
            slug = slugify(hostname)
            json_path = f"output_json/linux_output_{slug}.json"
            report_path = f"reports/report_{slug}.html"
            report_module = linuxReport

        # rename temp JSON output to its final host-specific name
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

    for idx, meta in enumerate(hosts_meta):
        nav_links = {
            # index.html is generated at the working directory root for this script
            "home": "../../index.html",
            "prev": (
                hosts_meta[idx - 1]["report_path"].split("/")[-1] if idx > 0 else None
            ),
            "next": (
                hosts_meta[idx + 1]["report_path"].split("/")[-1]
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
        )

        site_reports.append(result)

    # render a homepage linking to each generated report
    windowsReport.render_homepage(site_reports, output_path="index.html")

    print("Built:")
    for site in site_reports:
        print(f"  - {site['report_path']} ({site['hostname']})")
    print("  - index.html")


if __name__ == "__main__":
    main()
