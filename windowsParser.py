import os
import json
import re
import csv

# 09_Services_Details.csv
def parse_running_services(file_path):
    if not os.path.exists(file_path):
        return {"running_services": "no file found"}

    services = []

    with open(file_path, "r", encoding="utf-8-sig") as f:
        # Skip PowerShell metadata row
        first_line = f.readline()
        if first_line.startswith("#TYPE"):
            pass  # already skipped
        else:
            # rewind if no metadata (defensive)
            f.seek(0)

        reader = csv.DictReader(f)

        for row in reader:
            service_name = row.get("Name") or row.get("ServiceName")
            display_name = row.get("Description", "")
            responding = row.get("Responding", "")
                
            if responding.strip().lower() == "true":
                status = "running"
                active = "active"
            else:
                status = "stopped"
                active = "inactive"

            services.append({
                "service": service_name,
                "load": "loaded",
                "active": active,
                "status": status,
                "description": display_name
            })

    return {"running_services": services}

# 01_systeminfo.txt
def parse_systeminfo(file_path):
    if not os.path.exists(file_path):
        return {"systeminfo": "no file found"}

    data = {}
    current_key = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            # Skip header noise
            if not line or line.startswith("***"):
                continue

            # Match "Key: Value"
            if ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                data[key] = value
                current_key = key
            else:
                # Handle continuation lines (indented)
                if current_key:
                    data[current_key] += " " + line.strip()


    # Normalize processor block
    if "Processor(s)" in data:
        match = re.search(r"(\d+)\s+Processor", data["Processor(s)"])
        if match:
            data["Processor_Count"] = int(match.group(1))

    # Normalize memory (remove units if you want later comparisons)
    for key in ["Total Physical Memory", "Available Physical Memory"]:
        if key in data:
            data[key] = data[key].replace(" MB", "").replace(",", "")

    return {"systeminfo": data}

# 14_RDPSettings_Master.txt
def parse_rdp_master(file_path):
    if not os.path.exists(file_path):
        return {"rdp_master": "no file found"}

    data = {}

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip noise lines
            if not line or line.startswith("***") or line.startswith("Getting"):
                continue

            # Match "Key : Value"
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                value = parts[1].strip()

                # Skip WMI metadata fields (optional but cleaner)
                if key.startswith("__"):
                    continue

                data[key] = value

    return {"rdp_master": data}

# 14_RDPSettings_Domain.txt
def parse_rdp_domain(file_path):
    if not os.path.exists(file_path):
        return {"rdp_domain": "no file found"}

    data = {}
    in_properties = False

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            # Skip header/noise
            if not line or line.startswith("***") or line.startswith("Getting"):
                continue

            # Detect start of properties block
            if "Terminal Services" in line:
                in_properties = True
                continue

            if not in_properties:
                continue

            # Parse indented properties
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                value = parts[1].strip()

                if key:
                    data[key] = value

    return {"rdp_domain": data}

# 14_RDPSettings_Local.txt
def parse_rdp_local(file_path):
    if not os.path.exists(file_path):
        return {"rdp_local": "no file found"}

    data = {}
    in_properties = False

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            raw_line = line
            line = line.rstrip()

            # Skip noise
            if not line or line.startswith("***") or line.startswith("Getting"):
                continue

            # Detect start of the property section
            if line.strip().startswith("RDP-Tcp"):
                in_properties = True
                continue

            if not in_properties:
                continue

            # Parse indented key-value pairs
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                value = parts[1].strip()

                if key:
                    data[key] = value

    return {"rdp_local": data}

# 11_InstalledPatches.txt
def parse_installed_patches(file_path):
    if not os.path.exists(file_path):
        return {"installed_patches": "no file found"}

    patches = []
    in_table = False
    headers = []
    col_starts = []

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        stripped = line.rstrip("\n")

        if not stripped or stripped.startswith("***") or stripped.startswith("Getting"):
            continue

        # Header row
        if stripped.startswith("HotFixID"):
            headers = ["HotFixID", "InstalledOn", "Description", "InstalledBy"]

            # find column start positions dynamically
            col_starts = [
                stripped.find("HotFixID"),
                stripped.find("InstalledOn"),
                stripped.find("Description"),
                stripped.find("InstalledBy")
            ]

            continue

        # Separator row
        if stripped.startswith("--------"):
            in_table = True
            continue

        if not in_table:
            continue

        # Skip malformed lines
        if len(col_starts) < 4:
            continue

        # Slice columns using start indices
        hotfix_id = stripped[col_starts[0]:col_starts[1]].strip()
        installed_on = stripped[col_starts[1]:col_starts[2]].strip()
        description = stripped[col_starts[2]:col_starts[3]].strip()
        installed_by = stripped[col_starts[3]:].strip()

        if not hotfix_id:
            continue

        patches.append({
            "patch_id": hotfix_id,
            "installed_on": installed_on,
            "description": description,
            "installed_by": installed_by
        })

    return {"installed_patches": patches}

# 07_InstalledPrograms_wmioutput.txt
def parse_installed_programs_wmi(file_path):
    if not os.path.exists(file_path):
        return {"installed_programs": "no file found"}

    programs = []

    pattern = re.compile(
        r'IdentifyingNumber="\{([^}]+)\}",'
        r'Name="([^"]+)",'
        r'Version="([^"]+)"'
    )

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip noise/header lines
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or "Win32_Product" not in line
            ):
                continue

            match = pattern.search(line)
            if not match:
                continue

            guid, name, version = match.groups()

            programs.append({
                "id": guid,
                "name": name,
                "version": version
            })

    return {"installed_programs": programs}

# 05b_AuditPolicy.txt
def parse_audit_policy(file_path):
    if not os.path.exists(file_path):
        return {"audit_policy": "no file found"}

    data = {}
    current_category = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            # Skip noise
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or "Audit policy is defined" in line
                or "Category/Subcategory" in line
            ):
                continue

            # category lines
            if not line.startswith(" "):
                current_category = line.strip()
                data[current_category] = {}
                continue

            # subcategory line
            if current_category:
                # Split from right (most important fix)
                parts = re.split(r"\s{2,}", line.strip())

                if len(parts) >= 2:
                    name = parts[0].strip()
                    setting = parts[-1].strip()

                    if name:
                        data[current_category][name] = setting

    return {"audit_policy": data}

# 05_GroupPolicy.txt
def parse_group_policy(file_path):
    if not os.path.exists(file_path):
        return {"group_policy": "no file found"}

    result = {
        "account_policies": {},
        "audit_policy": {},
        "event_log_settings": {},
        "restricted_groups": {},
        "log_settings": {}
    }

    section = None
    current_group = None
    current_log = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            if not line or line.startswith("***") or line.startswith("Getting"):
                continue

            # Detect sections
            if "Account Policies" in line:
                section = "account"
                continue
            elif "Audit Policy" in line:
                section = "audit"
                continue
            elif "Event Log Settings" in line:
                section = "event_log"
                continue
            elif "Restricted Groups" in line:
                section = "groups"
                continue
            elif "Administrative Templates" in line:
                section = None  # we dont seem to really need this. if needed later, it can be added
                continue

            # Account Policies
            if section == "account" and "Policy:" in line:
                key = line.split("Policy:")[1].strip()
                continue

            if section == "account" and "Computer Setting:" in line:
                value = line.split("Computer Setting:")[1].strip()
                result["account_policies"][key] = value

            # Audit Policy
            if section == "audit" and "Policy:" in line:
                key = line.split("Policy:")[1].strip()
                continue

            if section == "audit" and "Computer Setting:" in line:
                value = line.split("Computer Setting:")[1].strip()
                result["audit_policy"][key] = value

            # Event Log Settings
            if section == "event_log" and "Log Name:" in line:
                current_log = line.split("Log Name:")[1].strip()
                result["event_log_settings"][current_log] = {}
                continue

            if section == "event_log" and "Policy:" in line:
                key = line.split("Policy:")[1].strip()
                continue

            if section == "event_log" and "Computer Setting:" in line:
                value = line.split("Computer Setting:")[1].strip()
                if current_log:
                    result["event_log_settings"][current_log][key] = value

            # Restricted Groups
            if section == "groups" and "Groupname:" in line:
                current_group = line.split("Groupname:")[1].strip()
                result["restricted_groups"][current_group] = []
                continue

            if section == "groups" and "Members:" in line:
                members = line.split("Members:")[1].strip()

                if members != "N/A" and current_group:
                    result["restricted_groups"][current_group].append(members)

            # multi-line group members
            if section == "groups" and current_group and line.strip().startswith("TLMGMT\\"):
                result["restricted_groups"][current_group].append(line.strip())

    return {"group_policy": result}

# 16_TimeSettings.txt
# This file is interesting because categories and subcategories can be formatted in different ways in this file
# So, I've divided it into 3 cases in the code, section+key on same line, key-value under existing section, and section-only lines.
# Going to hope this works for all cases, would not be surprised if this needs a patch in the future
def parse_time_settings(file_path):
    if not os.path.exists(file_path):
        return {"time_settings": "no file found"}

    data = {}
    current_section = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            raw_line = line
            line = line.rstrip()

            # Skip noise lines
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or line.startswith("Hive:")
                or line.startswith("Name")
                or line.startswith("----")
            ):
                continue

            # CASE 1: Section + key same line
            match = re.match(r'^(\S+)\s{2,}([^:]+?)\s*:\s*(.*)$', line)
            if match:
                section, key, value = match.groups()

                # initialize section
                current_section = section
                if current_section not in data:
                    data[current_section] = {}

                data[current_section][key.strip()] = value.strip()
                continue

            # CASE 2: Key-value under existing section
            match = re.match(r'^\s+([^:]+?)\s*:\s*(.*)$', line)
            if match and current_section:
                key, value = match.groups()
                data[current_section][key.strip()] = value.strip()
                continue

            # CASE 3: Section-only line
            if not line.startswith(" ") and ":" not in line:
                current_section = line.strip()
                if current_section not in data:
                    data[current_section] = {}

    return {"time_settings": data}

# 12_LocalAdmins.txt
def parse_local_admins(file_path):
    if not os.path.exists(file_path):
        return {"groups": "no file found"}

    group_name = "Administrators"
    members = []
    in_members = False

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip noise
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or line.startswith("Alias name")
                or line.startswith("Comment")
            ):
                continue

            # Detect members section
            if line == "Members":
                in_members = True
                continue

            if line.startswith("----"):
                continue

            if "command completed" in line.lower():
                break

            # Capture members
            if in_members:
                members.append(line)

    return {
        "groups": [
            {
                "group": group_name,
                "members": members
            }
        ]
    }

# 03_LocalUsers.txt
def parse_local_users(file_path):
    if not os.path.exists(file_path):
        return {"local_users": "no file found"}

    users = []

    pattern = re.compile(
        r'Domain="([^"]+)",Name="([^"]+)"'
    )

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip noise
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or "Win32_UserAccount" not in line
            ):
                continue

            match = pattern.search(line)
            if match:
                domain, username = match.groups()

                users.append({
                    "username": username,
                    "domain": domain
                })

    return {"local_users": users}

# 22_UserLogonHistory.txt
def parse_user_logon_history(file_path):
    if not os.path.exists(file_path):
        return {"user_logons": "no file found"}

    users = []

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Skip header
    for line in lines:
        line = line.rstrip()

        if (
            not line
            or line.startswith("***")
            or line.startswith("Getting")
            or "BadPasswordCount" in line
        ):
            continue

        # Split by multiple spaces
        parts = re.split(r"\s{2,}", line.strip())

        if len(parts) < 2:
            continue

        name = None
        last_logon = None
        num_logons = None

        # Find username (contains '\')
        for p in parts:
            if "\\" in p:
                name = p
                break

        # Find datetime-like value
        for p in parts:
            if re.match(r"\d{14}\.", p):
                last_logon = p
                break

        # Find number of logons (integer)
        for p in parts:
            if p.isdigit():
                num_logons = p

        if name:
            users.append({
                "user": name,
                "last_logon": last_logon,
                "logon_count": num_logons
            })

    return {"user_logons": users}

# 25_PasswordPolicies.txt
def parse_password_policies(file_path):
    if not os.path.exists(file_path):
        return {"password_policy": "no file found"}

    policies = {}

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip noise
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
                or "command completed" in line.lower()
            ):
                continue

            # Only process key:value lines
            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip()
            value = value.strip()

            if key:
                policies[key] = value

    return {"password_policy": policies}

# 00_Analysis.txt
# This one is a little weird. The format for this varies a lot
# This is a primal version but I assume this file may have different formats as the script changes
# Expect a patch or two to be needed here. Then again, this file isn't used too much
def parse_analysis(file_path):
    if not os.path.exists(file_path):
        return {"analysis": "no file found"}

    results = []
    current_entry = None

    pattern = re.compile(r'^(.*?):(\d+):\s*(.*)$')

    with open(file_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip()

            # Skip noise
            if (
                not line.strip()
                or line.startswith("***")
                or line.endswith("outputted above.")
            ):
                continue

            match = pattern.match(line.strip())

            # new entry
            if match:
                source_file, line_num, content = match.groups()

                current_entry = {
                    "source_file": source_file.strip(),
                    "line": int(line_num),
                    "content": content.strip()
                }

                results.append(current_entry)
                continue

            # continuation
            if current_entry:
                continuation = line.strip()
                if continuation:
                    current_entry["content"] += " " + continuation

    return {"analysis": results}

# 05_SecurityPolicies-local.txt
def parse_security_policies_local(file_path):
    if not os.path.exists(file_path):
        return {"security_policies_local": "no file found"}

    data = {}
    current_section = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line
            line = line.strip()

            # Skip noise
            if (
                not line
                or line.startswith("***")
                or line.startswith("Getting")
            ):
                continue

            # sections
            if line.startswith("[") and line.endswith("]"):
                current_section = line.strip("[]")

                # support duplicate sections → make list
                if current_section not in data:
                    data[current_section] = {}
                else:
                    # convert to list if duplicate appears
                    if not isinstance(data[current_section], list):
                        data[current_section] = [data[current_section]]
                    data[current_section].append({})
                
                continue

            # key-value pairs
            if "=" in line and current_section:
                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip()

                # handle duplicate sections list vs dict
                if isinstance(data[current_section], list):
                    data[current_section][-1][key] = value
                else:
                    data[current_section][key] = value

    return {"security_policies_local": data}

# 00_AllOutputs.txt
# Note: it seems that 05_SecurityPolicies-domain.txt is blank in the samples
# For this reason, we will be getting that from the corresponding section of 00_AllOutputs.txt
# This needs to be patched later. This first method gets that section
def extract_domain_security_policy(file_path):
    if not os.path.exists(file_path):
        return []

    lines = []
    in_section = False

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if "Getting security policies (domain)" in line:
                in_section = True
                continue

            if "Getting group policy results" in line:
                break

            if in_section:
                lines.append(line.rstrip("\n"))

    # print(lines)
    return lines

# This is the second part of that that parses the sectioned output
def parse_security_policies_domain(file_path):
    lines = extract_domain_security_policy(file_path)

    data = {}
    current_section = None

    for line in lines:
        raw = line
        line = line.strip()

        # Skip noise
        if (
            not line
            or line.startswith("***")
            or line.startswith("Getting")
        ):
            continue

        # sections
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")

            # support duplicate sections → make list
            if current_section not in data:
                data[current_section] = {}
            else:
                # convert to list if duplicate appears
                if not isinstance(data[current_section], list):
                    data[current_section] = [data[current_section]]
                data[current_section].append({})
            
            continue

        # key-value pairs
        if "=" in line and current_section:
            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip()

            # handle duplicate sections list vs dict
            if isinstance(data[current_section], list):
                data[current_section][-1][key] = value
            else:
                data[current_section][key] = value

    return {"security_policies_domain": data}

def build_windows_output(base_path="sampleWindows1", output_path= "windows_output.json"):
    output = {}

    output.update(parse_running_services(f"{base_path}/09_Services_Details.csv"))
    output.update(parse_systeminfo(f"{base_path}/01_systeminfo.txt"))
    output.update(parse_rdp_master(f"{base_path}/14_RDPSettings_Master.txt"))
    output.update(parse_rdp_domain(f"{base_path}/14_RDPSettings_Domain.txt"))
    output.update(parse_rdp_local(f"{base_path}/14_RDPSettings_Local.txt"))
    output.update(parse_installed_patches(f"{base_path}/11_InstalledPatches.txt"))
    output.update(parse_installed_programs_wmi(f"{base_path}/07_InstalledPrograms_wmioutput.txt"))
    output.update(parse_audit_policy(f"{base_path}/05b_AuditPolicy.txt"))
    output.update(parse_group_policy(f"{base_path}/05_GroupPolicy.txt"))
    output.update(parse_time_settings(f"{base_path}/16_TimeSettings.txt"))
    output.update(parse_local_admins(f"{base_path}/12_LocalAdmins.txt"))
    output.update(parse_local_users(f"{base_path}/03_LocalUsers.txt"))
    output.update(parse_user_logon_history(f"{base_path}/22_UserLogonHistory.txt"))
    output.update(parse_password_policies(f"{base_path}/25_PasswordPolicies.txt"))
    output.update(parse_analysis(f"{base_path}/00_Analysis.txt"))
    output.update(parse_security_policies_local(f"{base_path}/05_SecurityPolicies-local.txt"))
    output.update(parse_security_policies_domain(f"{base_path}/00_AllOutputs.txt"))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    return output

if __name__ == "__main__":
    result = build_windows_output()
    # print(json.dumps(result, indent=4))

"""
00_Analysis.txt

X 14_RDPSettings_Local.txt
X 14_RDPSettings_Domain.txt
X 14_RDPSettings_Master.txt

X 05_GroupPolicy.html
X 05b_AuditPolicy.txt
N/A 18_SnareSettings.txt

X 16_TimeSettings.txt
N/A 17_TimeState_Status.txt

X 12_LocalAdmins.txt
N/A 19_LocalRDPUsers.txt
N/A 20_LocalPowerUsers.txt
N/A 20_LocalServerOperators.txt

X 03_LocalUsers.txt
X 22_UserLogonHistory.txt

X 09_Services_Details.csv

X 11_InstalledPatches.txt

X 07_InstalledPrograms_*

X 25_PasswordPolicies.txt
"""