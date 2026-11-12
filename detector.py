"""Rule-based detector for suspicious login activity in authentication logs."""
import re
from collections import defaultdict, deque
from datetime import datetime

# ---- Tunable thresholds -------------------------------------------------
BF_THRESHOLD = 5        # failed logins (same IP + same user) ...
BF_WINDOW = 120         # ... within this many seconds = brute force
SPRAY_USERS = 4         # distinct usernames tried by one IP ...
SPRAY_WINDOW = 600      # ... within this many seconds = password spraying
BUSINESS_HOURS = (6, 22)  # successful logins outside 06:00-22:00 are flagged
# -------------------------------------------------------------------------

LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) LOGIN (?P<status>SUCCESS|FAILED) "
    r"user=(?P<user>\S+) ip=(?P<ip>\S+)$"
)


def parse_log(path):
    """Return a list of event dicts. Malformed lines are skipped."""
    events = []
    with open(path) as f:
        for line in f:
            m = LINE.match(line.strip())
            if m:
                events.append({
                    "time": datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S"),
                    "status": m["status"],
                    "user": m["user"],
                    "ip": m["ip"],
                })
    return sorted(events, key=lambda e: e["time"])


def detect(events):
    """Run all rules over the events and return a list of alert dicts."""
    alerts = []
    fails = defaultdict(deque)      # (ip, user) -> recent failure times
    active_bf = {}                  # (ip, user) -> alert currently growing
    spray = defaultdict(deque)      # ip -> recent (time, user) failures
    spray_alerted = {}              # ip -> alert currently growing

    for e in events:
        t, ip, user = e["time"], e["ip"], e["user"]
        key = (ip, user)

        # Drop failures that fell out of the brute-force window
        dq = fails[key]
        while dq and (t - dq[0]).total_seconds() > BF_WINDOW:
            dq.popleft()

        if e["status"] == "FAILED":
            dq.append(t)

            # Rule 1: brute force on a single account
            current = active_bf.get(key)
            if current and (t - current["_last"]).total_seconds() <= BF_WINDOW:
                current["count"] += 1
                current["_last"] = t
            elif len(dq) >= BF_THRESHOLD:
                a = _alert("HIGH", "BRUTE_FORCE", t, ip, user, len(dq),
                           f"{len(dq)} failed logins for '{user}' within {BF_WINDOW}s")
                active_bf[key] = a
                alerts.append(a)

            # Rule 2: password spraying across many accounts
            sq = spray[ip]
            sq.append((t, user))
            while sq and (t - sq[0][0]).total_seconds() > SPRAY_WINDOW:
                sq.popleft()
            distinct = {u for _, u in sq}
            current = spray_alerted.get(ip)
            if current and (t - current["_last"]).total_seconds() <= SPRAY_WINDOW:
                current["count"] += 1
                current["_last"] = t
            elif len(distinct) >= SPRAY_USERS:
                a = _alert("HIGH", "PASSWORD_SPRAYING", t, ip, "multiple", len(sq),
                           f"{len(distinct)} different accounts tried within {SPRAY_WINDOW}s")
                spray_alerted[ip] = a
                alerts.append(a)

        else:  # SUCCESS
            # Rule 3: success right after a burst of failures = possible compromise
            if len(dq) >= BF_THRESHOLD:
                alerts.append(_alert(
                    "CRITICAL", "SUCCESS_AFTER_FAILURES", t, ip, user, len(dq),
                    f"Login succeeded for '{user}' after {len(dq)} recent failures"))
            # Rule 4: successful login outside business hours
            if not (BUSINESS_HOURS[0] <= t.hour < BUSINESS_HOURS[1]):
                alerts.append(_alert(
                    "MEDIUM", "OFF_HOURS_LOGIN", t, ip, user, 1,
                    f"Successful login at {t:%H:%M}, outside business hours"))

    for a in alerts:
        a.pop("_last", None)
        # Alerts keep growing while an attack continues; refresh the final text
        if a["rule"] == "BRUTE_FORCE":
            a["detail"] = f"{a['count']} failed logins for '{a['user']}' in one burst"
        elif a["rule"] == "PASSWORD_SPRAYING":
            a["detail"] = f"{a['count']} failed attempts across multiple accounts from one IP"
    return alerts


def _alert(severity, rule, t, ip, user, count, detail):
    return {"time": f"{t:%Y-%m-%d %H:%M:%S}", "severity": severity, "rule": rule,
            "ip": ip, "user": user, "count": count, "detail": detail, "_last": t}


def summarize(events, alerts):
    """Headline numbers for the console and the dashboard."""
    failed = [e for e in events if e["status"] == "FAILED"]
    by_ip = defaultdict(int)
    for e in failed:
        by_ip[e["ip"]] += 1
    top_ips = sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:5]
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for a in alerts:
        sev[a["severity"]] += 1
    return {"total": len(events), "failed": len(failed),
            "severity": sev, "top_ips": top_ips}
