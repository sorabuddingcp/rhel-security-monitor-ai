# RHEL Security Monitor 2.0
##AUTH##Technical Skills Linux####
Lightweight RHEL 9/10 security monitoring agent with:

- SELinux AVC/USER_AVC detection
- SELinux enforcing/permissive/disabled drift
- firewalld configuration drift
- newly listening TCP/UDP ports
- world-writable permission drift
- new SUID/SGID files
- SSH/sudo authentication failure spikes
- new block devices and mounts
- insecure mount options
- hidden/unowned files in configured directories
- disk usage/spike alerts
- Gemini AI analysis for detected security events
- SMTP email alerts
- log rotation resilience
- systemd service

## Installation

```bash
dnf install -y python3 python3-pip audit firewalld iproute util-linux findutils
python3 -m pip install --upgrade google-genai
mkdir -p /etc/security-monitor /var/lib/security-monitor /opt/security-monitor
cp security_monitor.py /opt/security-monitor/
cp config.json /etc/security-monitor/
cp security-monitor.env /etc/security-monitor/
cp security-monitor.service /etc/systemd/system/
chmod 0750 /opt/security-monitor/security_monitor.py
chmod 0600 /etc/security-monitor/security-monitor.env
chmod 0600 /etc/security-monitor/config.json
chmod 0700 /var/lib/security-monitor
chown -R root:root /opt/security-monitor /etc/security-monitor /var/lib/security-monitor
```

Edit:

```bash
vi /etc/security-monitor/config.json
vi /etc/security-monitor/security-monitor.env
```

Put the Gemini key in `security-monitor.env`:

```bash
GEMINI_API_KEY=YOUR_REAL_KEY
```

Do not commit this file to Git.

Test:

```bash
python3 -m py_compile /opt/security-monitor/security_monitor.py
python3 -c 'from google import genai; import os; print("google-genai OK")'
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now auditd
systemctl enable --now security-monitor.service
systemctl status security-monitor.service
journalctl -u security-monitor.service -f
```

Agent log:

```bash
tail -f /var/log/security-monitor.log
```

## Gemini behavior

Rules detect the event first. Only detected security events are sent to Gemini.
If Gemini is unavailable, the agent still sends the normal rule-based email alert.
AI is advisory and must not be treated as the source of truth.

## Test

Port:
```bash
python3 -m http.server 9090 --bind 127.0.0.1
```

SELinux mode test, only during an approved maintenance window:
```bash
getenforce
setenforce 0
sleep 40
setenforce 1
```

Permission:
```bash
touch /root/security-monitor-test
chmod 777 /root/security-monitor-test
sleep 920
rm -f /root/security-monitor-test
```

Never test by changing production firewall rules or deleting system files.

## Security notes

- Run as root because audit logs, firewall state, mount state and system paths require privileged access.
- The agent does not make security changes.
- Keep the Gemini API key and SMTP credentials outside source code.
- Review and tune monitored paths and listening-port baseline for each server role.
- Restrict outbound network access to the required SMTP/Gemini endpoints if your policy requires it.
