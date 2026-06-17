# linuxParser.py
# Linux evidence parser that converts raw Linux host output files into
# normalized JSON structures for report generation.

import os
import json


# 1.2.5_running_services.txt
def parse_running_services(file_path):
    if not os.path.exists(file_path):
        return {"running_services": "no file found"}

    services = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            if line.startswith("Host "):
                continue
            if line.startswith("UNIT"):
                continue
            if (
                line.startswith("LOAD")
                or line.startswith("ACTIVE")
                or line.startswith("SUB")
                or ("loaded units listed. Pass --all" in line)
                or ("To show all installed unit files" in line)
            ):
                continue
            if "loaded units listed" in line:
                break

            parts = line.split()

            if len(parts) < 5:
                continue

            service_name = parts[0]
            load = parts[1]
            active = parts[2]
            sub = parts[3]

            description = " ".join(parts[4:])

            services.append(
                {
                    "service": service_name,
                    "load": load,
                    "active": active,
                    "status": sub,  # (running, dead, etc.)
                    "description": description,
                }
            )

    return {"running_services": services}


# uname.txt
def parse_uname(file_path):
    if not os.path.exists(file_path):
        return {"uname": "no file found"}

    with open(file_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if len(lines) < 2:
        return {"uname": "no valid data"}

    uname_line = lines[1]

    parts = uname_line.split()

    os_name = parts[0] if len(parts) > 0 else ""
    host = parts[1] if len(parts) > 1 else ""
    kernel = parts[2] if len(parts) > 2 else ""

    return {"uname": {"raw": uname_line, "os": os_name, "host": host, "kernel": kernel}}


# 8.3_sshd_config.txt
def parse_sshd_config(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"sshd_config": "no file found"}

    config = {}

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip junk
            if not line:
                continue
            if line.startswith("Host "):
                continue
            if line.startswith("#"):
                continue
            if line.startswith("###"):
                continue
            if line.startswith("####"):
                continue

            # Split into key + value
            parts = line.split(None, 1)

            if len(parts) < 2:
                continue

            key = parts[0]
            value = parts[1].strip()

            # Handle comma-separated lists
            if "," in value:
                value_list = [v.strip() for v in value.split(",") if v.strip()]
                config[key] = value_list
            else:
                config[key] = value

    return {"sshd_config": config}


# 6.3.3_update_history.txt
def parse_update_history(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"update_history": "no file found"}

    updates = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip junk
            if not line:
                continue
            if line.startswith("Host "):
                continue
            if line.startswith("ID"):
                continue
            if line.startswith("---"):
                continue

            if "|" not in line:
                continue

            parts = [p.strip() for p in line.split("|")]

            if len(parts) < 5:
                continue

            try:
                update_id = int(parts[0])
            except:
                continue

            command = parts[1]
            datetime_val = parts[2]
            action = parts[3]
            altered = parts[4]

            updates.append(
                {
                    "id": update_id,
                    "command": command,
                    "datetime": datetime_val,
                    "action": action,
                    "altered": altered,
                }
            )

    return {"update_history": updates}


import csv


# 6.3.3_package_manager.csv
def parse_package_manager(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"package_manager": "no file found"}

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            pkg_mgr = row.get("PkgMgr", "").strip()
            return {"package_manager": pkg_mgr}

    # Fallback if file is empty
    return {"package_manager": "no valid data"}


# summary.csv
# this file is like completely broken sometimes so this took forever
def parse_summary(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"summary": "no file found"}

    with open(file_path, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))

    if len(reader) < 3:
        return {"summary": "no valid data"}

    # summary.csv parsing is brittle and may need a patch if the source columns shift
    headers = [h.strip() for h in reader[1]]
    values = [v.strip() for v in reader[2]]

    summary = {}

    # Required columns for custom handling
    try:
        ip_idx = headers.index("IP")
        log_active_idx = headers.index("LogActive")
        log_level_idx = headers.index("LogLevel")
        timesync_idx = headers.index("TimesyncEnabled")
    except ValueError:
        return {"summary": "missing expected columns"}

    shifted = False
    offset = 0

    for i in range(log_active_idx + 1):
        key = headers[i]

        if key == "IP":
            raw_val = values[i] if i < len(values) else ""
            if raw_val == "":
                shifted = True
                offset = 1
                summary["IP"] = values[i + offset] if (i + offset) < len(values) else ""
            else:
                summary["IP"] = raw_val
            continue

        # If IP was blank, shift all columns after IP left by one
        source_idx = i + offset if shifted and i > ip_idx else i
        value = values[source_idx] if source_idx < len(values) else ""
        summary[key] = value

    tail_start = log_active_idx + 1 + offset if shifted else log_active_idx + 1
    tail = values[tail_start:] if tail_start < len(values) else []

    log_level = ""
    timesync_enabled = ""

    if tail:
        last = tail[-1].strip().upper() if tail[-1] is not None else ""

        if last in {"TRUE", "FALSE", ""}:
            timesync_enabled = tail[-1].strip() if tail[-1] is not None else ""
            log_parts = tail[:-1]
        else:
            log_parts = tail

        # Everything between LogActive and TimesyncEnabled belongs to LogLevel
        log_level = ",".join(
            part.strip() for part in log_parts if part is not None
        ).strip(",")

    summary["LogLevel"] = log_level
    summary["TimesyncEnabled"] = timesync_enabled

    return {"summary": summary}


# groups.txt
def parse_groups(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"groups": "no file found"}

    groups = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip junk
            if not line:
                continue
            if line.startswith("Host "):
                continue

            parts = line.split(":")

            if len(parts) < 4:
                continue

            group_name = parts[0]
            gid = parts[2]
            members_raw = parts[3]

            # Handle member list
            if members_raw:
                members = [m.strip() for m in members_raw.split(",") if m.strip()]
            else:
                members = []

            groups.append({"group": group_name, "gid": gid, "members": members})

    return {"groups": groups}


# 10.3.3_logging.txt
import os


def parse_logging(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"logging": "no file found"}

    forwarding_targets = []
    forwarding_configured = False
    script_result = ""

    with open(file_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line:
                continue
            if line.startswith("Host "):
                continue

            if "did not find any log forwarding targets" in line.lower():
                script_result = "no forwarding found"

            if line.startswith("#"):
                continue

            if "Target=" in line:
                forwarding_configured = True

                try:
                    start = line.index("Target=") + len("Target=")
                    target = line[start:].split()[0].replace('"', "").strip()
                    forwarding_targets.append(target)
                except:
                    pass

    if forwarding_configured and not script_result:
        script_result = "forwarding configured"

    if not script_result:
        script_result = "unknown"

    return {
        "logging": {
            "forwarding_configured": forwarding_configured,
            "forwarding_targets": forwarding_targets,
            "script_result": script_result,
        }
    }


# 10.6.1_timesync.txt
def parse_timesync(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"timesync": "no file found"}

    synchronized = None
    ntp_service = ""
    rtc_local_tz = ""

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            if line.startswith("Host "):
                continue

            if line.lower().startswith("system clock synchronized"):
                value = line.split(":", 1)[1].strip().lower()
                synchronized = value == "yes"

            elif line.lower().startswith("ntp service"):
                ntp_service = line.split(":", 1)[1].strip().lower()

            elif line.lower().startswith("rtc in local tz"):
                rtc_local_tz = line.split(":", 1)[1].strip().lower()

    return {
        "timesync": {
            "synchronized": synchronized,
            "ntp_service": ntp_service,
            "rtc_local_tz": rtc_local_tz,
        }
    }


# password.txt
import os


def parse_passwd(file_path):
    # File not found requirement
    if not os.path.exists(file_path):
        return {"passwd": "no file found"}

    users = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            if line.startswith("Host "):
                continue

            parts = line.split(":")

            if len(parts) < 7:
                continue

            username = parts[0]

            try:
                uid = int(parts[2])
            except:
                uid = None

            shell = parts[6]

            interactive = not any(x in shell for x in ["nologin", "false"])

            users.append(
                {
                    "username": username,
                    "uid": uid,
                    "shell": shell,
                    "interactive": interactive,
                }
            )

    return {"passwd": users}


# 6.3.3_repolist.txt
def parse_repolist(file_path):
    import os

    if not os.path.exists(file_path):
        return {"repolist": "no file found"}

    repos = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Host") or line.startswith("repo id"):
                continue

            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                repos.append({"repo_id": parts[0], "repo_name": parts[1]})

    return {"repolist": repos}


# sudoers.txt
def parse_sudoers(file_path):
    import os

    if not os.path.exists(file_path):
        return {"sudoers": "no file found"}

    privileges = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if (
                not line
                or line.startswith("#")
                or line.startswith("Defaults")
                or line.startswith("Host")
            ):
                continue

            parts = line.split()
            if len(parts) >= 3:
                privileges.append({"user": parts[0], "access": " ".join(parts[1:])})

    return {"sudoers": privileges}


# 8.2_enabledusers.txt
def parse_enabled_users(file_path):
    if not os.path.exists(file_path):
        return {"enabled_users": "no file found"}

    users = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Host "):
                continue

            parts = line.split(":")
            if len(parts) < 7:
                continue

            users.append(
                {
                    "username": parts[0],
                    "uid": int(parts[2]) if parts[2].isdigit() else None,
                    "comment": parts[4],
                    "shell": parts[6],
                }
            )

    return {"enabled_users": users}


# 8.2_last20logins.txt
def parse_last_logins(file_path):
    import os

    if not os.path.exists(file_path):
        return {"last_logins": "no file found"}

    logins = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Host") or line.startswith("wtmp"):
                continue

            parts = line.split()
            if len(parts) >= 3:
                logins.append({"user": parts[0], "source_ip": parts[2]})

    return {"last_logins": logins}


# 8.2.4_user_changes.txt
def parse_user_changes(file_path):
    import os

    if not os.path.exists(file_path):
        return {"user_changes": "no file found"}

    changes = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Host"):
                continue

            changes.append(line)

    return {"user_changes": changes}


# 8.2.8_tmout.txt
def parse_tmout(file_path):
    import os

    if not os.path.exists(file_path):
        return {"tmout": "no file found"}

    value = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Host"):
                continue

            if "=" in line:
                value = line.split("=")[-1].strip()

    return {"tmout": value}


# 10.6.2_timesources.txt
def parse_timesources(file_path):
    import os

    if not os.path.exists(file_path):
        return {"timesources": "no file found"}

    sources = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if (
                not line
                or line.startswith("Host")
                or line.startswith("=")
                or "MS Name" in line
            ):
                continue

            parts = line.split()
            if len(parts) >= 2:
                sources.append(parts[1])

    return {"timesources": sources}


# shadow.txt
def parse_shadow(file_path):
    import os

    if not os.path.exists(file_path):
        return {"shadow": "no file found"}

    entries = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            # Skip blanks and host line
            if not line or line.startswith("Host "):
                continue

            parts = line.split(":")

            # /etc/shadow should have 9 fields, but we’ll tolerate shorter rows
            if len(parts) < 2:
                continue

            username = parts[0]
            password_field = parts[1] if len(parts) > 1 else ""
            last_change = parts[2] if len(parts) > 2 else ""
            min_days = parts[3] if len(parts) > 3 else ""
            max_days = parts[4] if len(parts) > 4 else ""
            warn_days = parts[5] if len(parts) > 5 else ""
            inactive_days = parts[6] if len(parts) > 6 else ""
            expire_date = parts[7] if len(parts) > 7 else ""
            reserved = parts[8] if len(parts) > 8 else ""

            entries.append(
                {
                    "username": username,
                    "password_field": password_field,
                    "last_change": last_change,
                    "min_days": min_days,
                    "max_days": max_days,
                    "warn_days": warn_days,
                    "inactive_days": inactive_days,
                    "expire_date": expire_date,
                    "reserved": reserved,
                }
            )

    return {"shadow": entries}


# 8.3.9_pw-ages.csv
def parse_pw_ages(file_path):
    if not os.path.exists(file_path):
        return {"pw_ages": "no file found"}

    entries = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # adjust column names based on your CSV
            host = row.get("Host")
            user = row.get("User")
            pw_max_age = row.get("PwMaxAge")

            # normalize numeric values
            def normalize(val):
                if val is None or val == "":
                    return None
                try:
                    return int(val)
                except:
                    return val

            entries.append(
                {"host": host, "user": user, "pw_max_age": normalize(pw_max_age)}
            )

    return {"pw_ages": entries}


# 8.3.4_faillock.conf.txt
def parse_login_attempts(file_path):
    if not os.path.exists(file_path):
        return {"login_attempts": "no file found"}

    result = {
        "deny": "Not found",
        "unlock_time": "Not found",
        "even_deny_root": False,
        "root_unlock_time": "Not found",
    }

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Strip whitespace and skip comments and blank lines
            stripped = line.strip()
            stripped = stripped.replace("#", "").strip()
            if not stripped:
                continue

            if "=" in stripped:
                key, _, value = stripped.partition("=")
                key = key.strip()
                value = value.strip()
                # print(key, value)

                if key == "deny":
                    result["deny"] = value
                elif key == "unlock_time":
                    result["unlock_time"] = value
                elif "root_unlock_time" in key:
                    result["root_unlock_time"] = value
            elif "even_deny_root" in line and "`" not in line:
                # print(line)
                result["even_deny_root"] = True

    return {"login_attempts": result}


# 8.3_pwquality.txt
def parse_pwquality(file_path):
    if not os.path.exists(file_path):
        return {"pwquality": "no file found"}

    result = {}

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            # Skip blank lines and the timestamp header line
            if not stripped or stripped.startswith("#") or "Timestamp:" in stripped:
                continue

            if "=" in stripped:
                key, _, value = stripped.partition("=")
                result[key.strip()] = value.strip()

    return {"pwquality": result}


# this combines all the linux parse helpers into one json payload
def build_linux_output(base_path="sampleLinux", output_path="linux_output.json"):
    output = {}

    output.update(parse_running_services(f"{base_path}/1.2.5_running_services.txt"))
    output.update(parse_uname(f"{base_path}/uname.txt"))
    output.update(parse_sshd_config(f"{base_path}/8.3_sshd_config.txt"))
    output.update(parse_update_history(f"{base_path}/6.3.3_update_history.txt"))
    output.update(parse_package_manager(f"{base_path}/6.3.3_package_manager.csv"))
    output.update(parse_summary(f"{base_path}/summary.csv"))
    output.update(parse_groups(f"{base_path}/groups.txt"))
    output.update(parse_logging(f"{base_path}/10.3.3_logging.txt"))
    output.update(parse_timesync(f"{base_path}/10.6.1_timesync.txt"))
    output.update(parse_passwd(f"{base_path}/passwd.txt"))
    output.update(parse_repolist(f"{base_path}/6.3.3_repolist.txt"))
    output.update(parse_sudoers(f"{base_path}/sudoers.txt"))
    output.update(parse_enabled_users(f"{base_path}/8.2_enabledusers.txt"))
    output.update(parse_last_logins(f"{base_path}/8.2_last20logins.txt"))
    output.update(parse_user_changes(f"{base_path}/8.2.4_user_changes.txt"))
    output.update(parse_tmout(f"{base_path}/8.2.8_tmout.txt"))
    output.update(parse_timesources(f"{base_path}/10.6.2_timesources.txt"))
    output.update(parse_pw_ages(f"{base_path}/8.3.9_pw-ages.csv"))
    output.update(parse_shadow(f"{base_path}/shadow.txt"))
    output.update(parse_login_attempts(f"{base_path}/8.3.4_faillock.conf.txt"))
    output.update(parse_pwquality(f"{base_path}/8.3_pwquality.txt"))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    return output


if __name__ == "__main__":
    result = build_linux_output()
    # print(json.dumps(result, indent=4))
