#!/usr/bin/env python3
"""
RHEL 9/10 Lightweight Security Monitor
Rule-based detection + optional Gemini AI analysis + SMTP alerts.

The agent is intentionally read-only: it does not change SELinux,
firewalld, mounts, permissions, users, or processes.
"""

import json
import logging
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

try:
    from google import genai
except ImportError:
    genai = None

VERSION = "2.0.0"
CONFIG = "/etc/security-monitor/config.json"
ENV_FILE = "/etc/security-monitor/security-monitor.env"
STATE = "/var/lib/security-monitor/state.json"
LOG = "/var/log/security-monitor.log"

Path("/var/lib/security-monitor").mkdir(mode=0o700, parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOG,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("security-monitor")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def run(cmd, timeout=20):
    try:
        p = subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_config():
    cfg = load_json(CONFIG, None)
    if not cfg:
        raise RuntimeError(f"Cannot read {CONFIG}")
    return cfg


def load_state():
    return load_json(STATE, {
        "initialized": False,
        "selinux": None,
        "ports": [],
        "firewall": None,
        "mounts": [],
        "devices": [],
        "risky_permissions": {},
        "suid_sgid": {},
        "hidden_files": {},
        "unowned_files": {},
        "disk": {},
        "auth": {},
        "last_alert": {}
    })


def local_ips():
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    ips = []
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if m:
                ips.append(m.group(1))
    return sorted(set(ips))


class GeminiAnalyzer:
    def __init__(self, cfg):
        g = cfg.get("gemini", {})
        self.enabled = bool(g.get("enabled", True))
        self.model = g.get("model", "gemini-3.8-flash")
        self.client = None
        if self.enabled and genai is not None and os.getenv("GEMINI_API_KEY"):
            try:
                self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            except Exception:
                log.exception("Gemini client initialization failed")

    def analyze(self, category, description, evidence):
        if not self.enabled:
            return None
        if self.client is None:
            log.warning("Gemini unavailable; sending rule-based alert only")
            return None

        prompt = f"""
You are a senior Linux security analyst specializing in RHEL 9 and RHEL 10.
Analyze the security event below. Use ONLY the supplied evidence; do not
invent facts. The analysis is advisory and must not recommend destructive
commands without verification.

CATEGORY:
{category}

DESCRIPTION:
{description}

EVIDENCE:
{evidence[:12000]}

Return concise JSON with exactly these fields:
severity: one of LOW, MEDIUM, HIGH, CRITICAL
threat: short description
analysis: what the evidence indicates
likely_cause: likely cause, or "Unknown from available evidence"
recommended_action: practical verification/remediation steps
false_positive_likelihood: one of LOW, MEDIUM, HIGH
"""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            text = (response.text or "").strip()
            if not text:
                return None
            # Gemini may return a fenced JSON block.
            text = re.sub(r"^```json\s*", "", text, flags=re.I)
            text = re.sub(r"\s*```$", "", text)
            data = json.loads(text)
            required = {
                "severity", "threat", "analysis",
                "likely_cause", "recommended_action",
                "false_positive_likelihood"
            }
            if not required.issubset(data):
                return None
            return data
        except Exception as e:
            log.error("Gemini analysis failed: %s", e)
            return None


class AlertManager:
    def __init__(self, cfg, state, ai):
        self.cfg = cfg
        self.state = state
        self.ai = ai
        self.cooldown = int(cfg.get("alerting", {}).get("cooldown_seconds", 300))

    def allowed(self, key):
        last = self.state.setdefault("last_alert", {}).get(key, 0)
        if time.time() - last < self.cooldown:
            return False
        self.state["last_alert"][key] = time.time()
        return True

    def send(self, category, description, evidence, remediation):
        key = category + ":" + description[:200]
        if not self.allowed(key):
            return

        ai_result = self.ai.analyze(category, description, evidence)

        email = self.cfg.get("email", {})
        smtp_host = email.get("smtp_host")
        sender = email.get("sender")
        recipient = email.get("recipient")
        if not smtp_host or not sender or not recipient:
            log.error("Incomplete SMTP configuration")
            return

        severity = "UNASSESSED"
        ai_section = "Gemini analysis unavailable; rule-based detection remains active."

        if ai_result:
            severity = ai_result["severity"].upper()
            ai_section = (
                f"Severity: {severity}\n"
                f"Threat: {ai_result['threat']}\n"
                f"Analysis: {ai_result['analysis']}\n"
                f"Likely cause: {ai_result['likely_cause']}\n"
                f"Recommended action: {ai_result['recommended_action']}\n"
                f"False-positive likelihood: {ai_result['false_positive_likelihood']}"
            )

        subject = f"[SECURITY][{severity}] {category} {socket.gethostname()}"
        body = f"""RHEL Security Monitor {VERSION}

Timestamp : {now_iso()}
Hostname  : {socket.gethostname()}
IP        : {", ".join(local_ips()) or "unknown"}
Category  : {category}

Detection
---------
{description}

Evidence
--------
{evidence[:12000]}

Rule-based remediation
----------------------
{remediation}

Gemini AI Analysis
------------------
{ai_section}

Note: Gemini analysis is advisory. Verify evidence on the host before
taking remediation actions.
"""

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.set_content(body)

        try:
            port = int(email.get("smtp_port", 587))
            user = email.get("username") or os.getenv("SMTP_USERNAME")
            password = email.get("password") or os.getenv("SMTP_PASSWORD")
            context = ssl.create_default_context()

            if bool(email.get("starttls", True)):
                with smtplib.SMTP(smtp_host, port, timeout=20) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    if user:
                        smtp.login(user, password or "")
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP_SSL(smtp_host, port, context=context, timeout=20) as smtp:
                    if user:
                        smtp.login(user, password or "")
                    smtp.send_message(msg)

            log.warning("Alert sent: %s severity=%s", category, severity)
        except Exception:
            log.exception("SMTP alert failed for %s", category)


class Tailer:
    def __init__(self, path):
        self.path = path
        self.f = None
        self.inode = None
        self.pos = 0

    def read_new(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        except Exception:
            log.exception("stat failed: %s", self.path)
            return []

        if self.f is None or self.inode != st.st_ino or st.st_size < self.pos:
            if self.f:
                try: self.f.close()
                except Exception: pass
            try:
                self.f = open(self.path, "r", encoding="utf-8", errors="replace")
                self.inode = st.st_ino
                self.f.seek(0, os.SEEK_END)
                self.pos = self.f.tell()
            except Exception:
                log.exception("open failed: %s", self.path)
                self.f = None
                return []

        lines = []
        while True:
            line = self.f.readline()
            if not line:
                break
            self.pos = self.f.tell()
            lines.append(line.rstrip())
        return lines


def selinux_mode():
    rc, out, _ = run(["getenforce"])
    return out.lower() if rc == 0 else "unknown"


def firewall_state():
    rc, out, err = run(["firewall-cmd", "--get-active-zones"])
    if rc != 0:
        return {"available": False, "error": err}
    zones = {}
    current = None
    for line in out.splitlines():
        if line and not line.startswith(" "):
            current = line.strip()
            zones[current] = {}
    for zone in zones:
        for opt in ("--list-ports", "--list-services", "--list-rich-rules", "--list-sources"):
            rc, out, _ = run(["firewall-cmd", "--zone", zone, opt])
            zones[zone][opt] = out if rc == 0 else ""
    return {"available": True, "zones": zones}


def listening_ports():
    rc, out, _ = run(["ss", "-H", "-lntu"])
    ports = set()
    if rc != 0:
        return []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto = "tcp" if f[0].startswith("tcp") else "udp" if f[0].startswith("udp") else None
        if not proto:
            continue
        m = re.search(r":(\d+)$", f[4].strip("[]"))
        if m:
            ports.add(f"{proto}/{m.group(1)}")
    return sorted(ports)


def mounts():
    rc, out, _ = run(["findmnt", "-rn", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"])
    result = []
    if rc != 0:
        return result
    for line in out.splitlines():
        f = line.split(None, 3)
        if len(f) == 4:
            result.append({
                "source": f[0], "target": f[1], "fstype": f[2],
                "options": sorted(f[3].split(","))
            })
    return result


def devices():
    rc, out, _ = run(["lsblk", "-dn", "-o", "NAME,TYPE,SIZE"])
    result = []
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 3:
                result.append({"name": f[0], "type": f[1], "size": f[2]})
    return result


def permission_scan(paths):
    risky, suid = {}, {}
    for root in paths:
        if not os.path.exists(root):
            continue
        cmd = [
            "find", root, "-xdev", "-type", "f",
            "(", "-perm", "-0002", "-o", "-perm", "/6000", ")",
            "-printf", "%m %u %g %p\\n"
        ]
        rc, out, _ = run(cmd, timeout=180)
        if rc != 0:
            continue
        for line in out.splitlines():
            f = line.split(None, 3)
            if len(f) != 4:
                continue
            mode, owner, group, path = f
            try: mi = int(mode, 8)
            except ValueError: continue
            d = {"mode": mode, "owner": owner, "group": group}
            if mi & 0o002: risky[path] = d
            if mi & 0o6000: suid[path] = d
    return risky, suid


def storage_files(paths):
    hidden, unowned = set(), set()
    for root in paths:
        if not os.path.isdir(root):
            continue
        rc, out, _ = run(["find", root, "-xdev", "-type", "f", "-printf", "%u:%g %p\\n"], timeout=180)
        if rc != 0:
            continue
        for line in out.splitlines():
            f = line.split(None, 1)
            if len(f) != 2: continue
            owner, path = f
            if os.path.basename(path).startswith("."): hidden.add(path)
            if owner.startswith("nouser") or owner.startswith("nogroup"): unowned.add(path)
    return sorted(hidden), sorted(unowned)


def disk_usage():
    rc, out, _ = run(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs"])
    result = {}
    if rc != 0: return result
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 6: continue
        try: used = int(f[4].rstrip("%"))
        except ValueError: continue
        result[f[5]] = {"filesystem": f[0], "used_percent": used}
    return result


def process_audit(line, alerts, state, cfg):
    if "type=AVC" in line or "type=USER_AVC" in line or "avc:  denied" in line:
        alerts.send(
            "SELINUX_DENIAL",
            "SELinux denied an operation.",
            line[-6000:],
            "Use ausearch/audit logs to identify the subject, target and denied operation. "
            "Do not create a broad allow rule without validating the cause."
        )

    lower = line.lower()
    ssh = "sshd" in lower and any(x in lower for x in (
        "failed password", "authentication failure", "invalid user",
        "maximum authentication attempts exceeded"
    ))
    sudo = "sudo" in lower and any(x in lower for x in (
        "authentication failure", "incorrect password", "conversation failed"
    ))
    if not ssh and not sudo:
        return

    cat = "SSH_AUTH_FAILURE" if ssh else "SUDO_AUTH_FAILURE"
    m = re.search(r"(?:from|rhost=)([0-9a-fA-F:.]+)", line)
    source = m.group(1) if m else "unknown"
    key = f"{cat}:{source}"
    ent = state.setdefault("auth", {}).setdefault(key, {"count": 0, "start": time.time()})
    window = int(cfg.get("auth_monitor", {}).get("window_seconds", 300))
    threshold = int(cfg.get("auth_monitor", {}).get("failure_threshold", 5))
    if time.time() - ent["start"] > window:
        ent["count"], ent["start"] = 0, time.time()
    ent["count"] += 1
    if ent["count"] >= threshold:
        alerts.send(
            cat,
            f"{ent['count']} authentication failures from {source} in {window} seconds.",
            line[-6000:],
            "Verify the source, account and SSH/sudo configuration. "
            "Use key-based SSH authentication and appropriate rate limiting where approved."
        )
        ent["count"], ent["start"] = 0, time.time()


def check_state(state, cfg, alerts):
    current = selinux_mode()
    if state["selinux"] is not None and state["selinux"] != current:
        alerts.send(
            "SELINUX_STATE_CHANGE",
            f"SELinux mode changed from {state['selinux']} to {current}.",
            f"Command: getenforce\nCurrent: {current}",
            "Verify who changed SELinux mode and why. Restore enforcing after approved testing."
        )
    state["selinux"] = current

    fw = firewall_state()
    if fw.get("available"):
        if state["firewall"] is not None and state["firewall"] != fw:
            alerts.send(
                "FIREWALL_CHANGE",
                "firewalld active-zone configuration changed.",
                json.dumps(fw, indent=2)[:10000],
                "Review changed ports, services, sources and rich rules and verify the administrator/process responsible."
            )
        state["firewall"] = fw

    current_ports = listening_ports()
    baseline = set(cfg.get("network", {}).get("allowed_listening_ports", []))
    old = set(state.get("ports", []))
    if state["initialized"]:
        for p in sorted(set(current_ports) - (old | baseline)):
            alerts.send(
                "PORT_OPENED",
                f"New listening port detected: {p}",
                "ss -lntup\n" + "\n".join(current_ports),
                "Identify the process with ss -lntup/lsof, verify it is approved, and review firewall exposure."
            )
    state["ports"] = current_ports

    cur_mounts = mounts()
    old_mounts = {(m["source"], m["target"], m["fstype"]) for m in state.get("mounts", [])}
    allowed = cfg.get("storage", {}).get("allowed_mounts", [])
    allowed_sources = {x.get("source") for x in allowed}
    allowed_targets = {x.get("target") for x in allowed}
    if state["initialized"]:
        for m in cur_mounts:
            ident = (m["source"], m["target"], m["fstype"])
            if ident not in old_mounts and m["source"] not in allowed_sources and m["target"] not in allowed_targets:
                alerts.send(
                    "NEW_MOUNT",
                    f"New filesystem mount: {m['source']} -> {m['target']}",
                    json.dumps(m, indent=2),
                    "Verify the mount source, purpose, /etc/fstab and recent administrative activity."
                )
    state["mounts"] = cur_mounts

    cur_devices = devices()
    old_devices = {d["name"] for d in state.get("devices", [])}
    if state["initialized"]:
        for d in cur_devices:
            if d["name"] not in old_devices and d["type"] in ("disk", "loop", "part"):
                alerts.send(
                    "NEW_BLOCK_DEVICE",
                    f"New block device detected: {d['name']}",
                    json.dumps(d, indent=2),
                    "Verify the device is expected and investigate how it was attached."
                )
    state["devices"] = cur_devices

    required = cfg.get("storage", {}).get("required_mount_options", {})
    for m in cur_mounts:
        if m["target"] not in required:
            continue
        missing = [x for x in required[m["target"]] if x not in set(m["options"])]
        if missing:
            alerts.send(
                "INSECURE_MOUNT",
                f"{m['target']} is missing required options: {', '.join(missing)}",
                json.dumps(m, indent=2),
                "Review /etc/fstab and remount using the approved nodev/nosuid/noexec policy."
            )


def check_expensive(state, cfg, alerts):
    risky, suid = permission_scan(cfg.get("permission_monitor", {}).get(
        "paths", ["/etc", "/usr/bin", "/usr/sbin", "/root"]
    ))
    if state["initialized"]:
        for path, d in risky.items():
            if path not in state["risky_permissions"]:
                alerts.send(
                    "PERMISSION_DRIFT",
                    f"World-writable file detected: {path}",
                    json.dumps(d, indent=2),
                    "Verify ownership and remove world-write permission unless explicitly required."
                )
        for path, d in suid.items():
            if path not in state["suid_sgid"]:
                alerts.send(
                    "SUID_SGID_DRIFT",
                    f"New SUID/SGID file detected: {path}",
                    json.dumps(d, indent=2),
                    "Verify package ownership and whether the privilege bit is expected."
                )
    state["risky_permissions"] = risky
    state["suid_sgid"] = suid

    hidden, unowned = storage_files(cfg.get("storage", {}).get("monitor_directories", []))
    if state["initialized"]:
        for p in set(hidden) - set(state["hidden_files"]):
            alerts.send(
                "NEW_HIDDEN_FILE",
                f"New hidden file detected: {p}",
                f"Path: {p}",
                "Verify owner, permissions, timestamps and the process that created/accessed the file."
            )
        for p in set(unowned) - set(state["unowned_files"]):
            alerts.send(
                "UNOWNED_FILE",
                f"File has unresolved owner/group: {p}",
                f"Path: {p}",
                "Verify filesystem integrity and package/application ownership."
            )
    state["hidden_files"] = {p: True for p in hidden}
    state["unowned_files"] = {p: True for p in unowned}

    disk = disk_usage()
    scfg = cfg.get("storage", {})
    threshold = int(scfg.get("disk_usage_alert_percent", 85))
    spike = int(scfg.get("disk_usage_spike_percent", 15))
    for mp, d in disk.items():
        old = state["disk"].get(mp, {}).get("used_percent")
        if d["used_percent"] >= threshold:
            alerts.send(
                "DISK_USAGE_HIGH",
                f"Filesystem {mp} is {d['used_percent']}% full.",
                json.dumps(d, indent=2),
                "Identify large files/log growth and investigate unexpected data staging."
            )
        if old is not None and d["used_percent"] - old >= spike:
            alerts.send(
                "DISK_USAGE_SPIKE",
                f"Filesystem {mp} increased from {old}% to {d['used_percent']}%.",
                json.dumps(d, indent=2),
                "Investigate recent file creation, logs and possible unauthorized data staging."
            )
    state["disk"] = disk


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        return 1

    cfg = load_config()
    state = load_state()

    ai = GeminiAnalyzer(cfg)
    alerts = AlertManager(cfg, state, ai)

    audit = Tailer(cfg.get("logs", {}).get("audit_log", "/var/log/audit/audit.log"))
    secure = Tailer(cfg.get("logs", {}).get("secure_log", "/var/log/secure"))

    state_every = int(cfg.get("intervals", {}).get("state_check_seconds", 30))
    expensive_every = int(cfg.get("intervals", {}).get("permission_scan_seconds", 900))
    next_state = 0
    next_expensive = 0

    log.info("security-monitor %s started; Gemini=%s model=%s",
             VERSION, bool(ai.client), ai.model)

    while True:
        try:
            for line in audit.read_new():
                process_audit(line, alerts, state, cfg)
            for line in secure.read_new():
                process_audit(line, alerts, state, cfg)

            now = time.monotonic()
            if now >= next_state:
                check_state(state, cfg, alerts)
                next_state = now + state_every

            if now >= next_expensive:
                check_expensive(state, cfg, alerts)
                next_expensive = now + expensive_every

            state["initialized"] = True
            save_json(STATE, state)
            time.sleep(5)
        except KeyboardInterrupt:
            break
        except Exception:
            log.exception("monitor loop error")
            time.sleep(10)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
