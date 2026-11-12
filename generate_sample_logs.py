"""Generate a synthetic authentication log for testing the detector.

All data is fake. IPs come from documentation ranges (RFC 5737), so they
never point at real machines.
"""
import random
from datetime import datetime, timedelta

random.seed(42)

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "admin", "teller01"]
NORMAL_IPS = [f"198.51.100.{i}" for i in range(10, 20)]
START = datetime(2026, 11, 1, 8, 0, 0)

events = []

# 1) Normal business-hours activity (about 5% of attempts fail by typo)
for _ in range(400):
    t = START + timedelta(seconds=random.randint(0, 12 * 3600))
    user = random.choice(USERS[:6])
    ip = random.choice(NORMAL_IPS)
    status = "FAILED" if random.random() < 0.05 else "SUCCESS"
    events.append((t, user, ip, status))

# 2) Brute force: one IP hammers one account, then gets in
bf_start = START + timedelta(hours=3)
for i in range(14):
    events.append((bf_start + timedelta(seconds=i * 8), "admin", "203.0.113.50", "FAILED"))
events.append((bf_start + timedelta(seconds=130), "admin", "203.0.113.50", "SUCCESS"))

# 3) Password spraying: one IP tries many different accounts
spray_start = START + timedelta(hours=7)
for i, user in enumerate(USERS * 2):
    events.append((spray_start + timedelta(seconds=i * 20), user, "203.0.113.77", "FAILED"))

# 4) A successful login at 02:41, outside business hours
events.append((datetime(2026, 11, 1, 2, 41, 5), "teller01", "198.51.100.99", "SUCCESS"))

events.sort()
with open("logs/sample_auth.log", "w") as f:
    for t, user, ip, status in events:
        f.write(f"{t:%Y-%m-%d %H:%M:%S} LOGIN {status} user={user} ip={ip}\n")

print(f"Wrote {len(events)} events to logs/sample_auth.log")
