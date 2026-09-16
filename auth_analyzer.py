import csv
from collections import defaultdict
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "auth_logs.csv"

# Number of failed logins required before we consider
# an account suspicious.
FAILED_LOGIN_THRESHOLD = 3

# Accounts that have elevated privileges.
# In a real environment, this would come from AD.
PRIVILEGED_ACCOUNTS = {
    "admin",
    "administrator",
    "david"
}

# Normal working hours for this training environment.
NORMAL_START_HOUR = 8
NORMAL_END_HOUR = 18


# ============================================================
# DATA STORAGE
# ============================================================

events = []

failed_logins = defaultdict(list)
successful_logins = defaultdict(list)
source_ips = defaultdict(set)


# ============================================================
# LOAD LOG FILE
# ============================================================

try:
    with open(LOG_FILE, "r", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

            # Convert the event ID from text to an integer.
            row["event_id"] = int(row["event_id"])

            # Convert the timestamp into a Python datetime object.
            row["datetime"] = datetime.strptime(
                row["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            events.append(row)

except FileNotFoundError:
    print(f"[ERROR] Could not find {LOG_FILE}")
    print("Make sure auth_logs.csv is in the same folder.")
    exit()


# ============================================================
# ANALYZE EVENTS
# ============================================================

for event in events:

    username = event["username"]
    source_ip = event["source_ip"]
    event_id = event["event_id"]

    # Keep track of every IP address used by each account.
    source_ips[username].add(source_ip)

    # Event ID 4625 = failed Windows logon.
    if event_id == 4625:

        failed_logins[username].append(event)

    # Event ID 4624 = successful Windows logon.
    elif event_id == 4624:

        successful_logins[username].append(event)


# ============================================================
# DISPLAY BASIC SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("WINDOWS AUTHENTICATION ANALYZER")
print("=" * 60)

print(f"\nTotal events analyzed: {len(events)}")


# ============================================================
# DETECTION 1 — MULTIPLE FAILED LOGINS
# ============================================================

print("\n[1] MULTIPLE FAILED LOGIN DETECTION")
print("-" * 60)

for username, failures in failed_logins.items():

    count = len(failures)

    if count >= FAILED_LOGIN_THRESHOLD:

        print(
            f"[ALERT] {username} had "
            f"{count} failed login attempts."
        )


# ============================================================
# DETECTION 2 — FAILED LOGINS FOLLOWED BY SUCCESS
# ============================================================

print("\n[2] FAILED LOGINS FOLLOWED BY SUCCESS")
print("-" * 60)

for username, failures in failed_logins.items():

    successes = successful_logins.get(username, [])

    if not successes:
        continue

    # Sort events chronologically.
    failures.sort(key=lambda event: event["datetime"])
    successes.sort(key=lambda event: event["datetime"])

    for success in successes:

        failures_before_success = [
            failure
            for failure in failures
            if failure["datetime"] < success["datetime"]
        ]

        if len(failures_before_success) >= FAILED_LOGIN_THRESHOLD:

            print(
                f"[ALERT] {username}: "
                f"{len(failures_before_success)} failed "
                f"logins followed by a successful login "
                f"at {success['time']}."
            )

            break


# ============================================================
# DETECTION 3 — UNUSUAL LOGIN HOURS
# ============================================================

print("\n[3] UNUSUAL LOGIN TIME DETECTION")
print("-" * 60)

for event in events:

    hour = event["datetime"].hour

    # Ignore normal working hours.
    if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:

        print(
            f"[ALERT] {event['username']} logged in at "
            f"{event['time']} from {event['source_ip']}."
        )


# ============================================================
# DETECTION 4 — MULTIPLE SOURCE IPs
# ============================================================

print("\n[4] MULTIPLE SOURCE IP DETECTION")
print("-" * 60)

for username, ips in source_ips.items():

    if len(ips) > 1:

        print(
            f"[ALERT] {username} authenticated from "
            f"{len(ips)} different IP addresses:"
        )

        for ip in ips:
            print(f"        - {ip}")


# ============================================================
# DETECTION 5 — PRIVILEGED ACCOUNT ACTIVITY
# ============================================================

print("\n[5] PRIVILEGED ACCOUNT ACTIVITY")
print("-" * 60)

for event in events:

    username = event["username"]

    if username.lower() in {
        account.lower()
        for account in PRIVILEGED_ACCOUNTS
    }:

        print(
            f"[INFO] Privileged account activity: "
            f"{username} | "
            f"Event {event['event_id']} | "
            f"{event['time']} | "
            f"{event['source_ip']}"
        )


# ============================================================
# DETECTION 6 — SIMPLE RISK SCORING
# ============================================================

print("\n[6] RISK SCORING")
print("-" * 60)

risk_scores = defaultdict(int)

for username, failures in failed_logins.items():

    # Multiple failures increase risk.
    if len(failures) >= FAILED_LOGIN_THRESHOLD:

        risk_scores[username] += 30

    # Many different IP addresses increase risk.
    if len(source_ips[username]) > 1:

        risk_scores[username] += 20


# Check successful logins occurring after multiple failures.
for username, failures in failed_logins.items():

    successes = successful_logins.get(username, [])

    if not successes:
        continue

    for success in successes:

        failures_before_success = [
            failure
            for failure in failures
            if failure["datetime"] < success["datetime"]
        ]

        if len(failures_before_success) >= FAILED_LOGIN_THRESHOLD:

            risk_scores[username] += 30
            break


# Check unusual login times.
for event in events:

    hour = event["datetime"].hour

    if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:

        risk_scores[event["username"]] += 10


# Privileged accounts receive additional attention.
for username in risk_scores:

    if username.lower() in {
        account.lower()
        for account in PRIVILEGED_ACCOUNTS
    }:

        risk_scores[username] += 20


# ============================================================
# DISPLAY RISK SCORES
# ============================================================

for username, score in sorted(
    risk_scores.items(),
    key=lambda item: item[1],
    reverse=True
):

    if score >= 70:
        severity = "HIGH"

    elif score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    print(
        f"{username:<15} "
        f"Score: {score:<3} "
        f"Severity: {severity}"
    )


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("INVESTIGATION SUMMARY")
print("=" * 60)

if not risk_scores:

    print("\nNo suspicious authentication patterns detected.")

else:

    for username, score in sorted(
        risk_scores.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(
            f"\nAccount: {username}"
        )

        print(
            f"Risk score: {score}"
        )

        print(
            f"Source IPs: "
            f"{', '.join(source_ips[username])}"
        )

        print(
            f"Failed logins: "
            f"{len(failed_logins.get(username, []))}"
        )

        print(
            f"Successful logins: "
            f"{len(successful_logins.get(username, []))}"
        )

print("\nAnalysis complete.")
