import csv
from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# WINDOWS AUTHENTICATION ANALYZER
# ============================================================
# A defensive security tool for analyzing Windows authentication
# logs and identifying suspicious login patterns.
#
# Detects:
# 1. Multiple failed login attempts
# 2. Failed logins followed by a successful login
# 3. Suspicious activity within a defined time window
# 4. Logins outside normal working hours
# 5. Authentication from multiple source IP addresses
# 6. Privileged account activity
# 7. Risk scoring based on multiple indicators
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "auth_logs.csv"

# Minimum number of failed attempts required to trigger detection.
FAILED_LOGIN_THRESHOLD = 3

# Time window used for brute-force-style detection.
FAILED_LOGIN_WINDOW = timedelta(minutes=5)

# Normal working hours.
NORMAL_START_HOUR = 8
NORMAL_END_HOUR = 18

# Accounts considered privileged in this training environment.
PRIVILEGED_ACCOUNTS = {
    "admin",
    "administrator",
    "david"
}


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
    with open(LOG_FILE, "r", newline="", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        for row in reader:

            # Convert Event ID from text into an integer.
            row["event_id"] = int(row["event_id"])

            # Convert timestamp into a datetime object.
            row["datetime"] = datetime.strptime(
                row["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            events.append(row)

except FileNotFoundError:

    print(f"[ERROR] Could not find {LOG_FILE}.")
    print("Make sure auth_logs.csv is in the same directory.")
    raise SystemExit


# ============================================================
# SORT EVENTS
# ============================================================

# Sorting makes chronological analysis easier and ensures
# detection logic processes events in the correct order.
events.sort(key=lambda event: event["datetime"])


# ============================================================
# CLASSIFY EVENTS
# ============================================================

for event in events:

    username = event["username"]
    source_ip = event["source_ip"]
    event_id = event["event_id"]

    # Track all source IP addresses associated with an account.
    source_ips[username].add(source_ip)

    # Windows Event ID 4625 = failed logon.
    if event_id == 4625:

        failed_logins[username].append(event)

    # Windows Event ID 4624 = successful logon.
    elif event_id == 4624:

        successful_logins[username].append(event)


# ============================================================
# HEADER
# ============================================================

print("\n" + "=" * 65)
print("WINDOWS AUTHENTICATION ANALYZER")
print("=" * 65)

print(f"\nTotal events analyzed: {len(events)}")
print(f"Failed login threshold: {FAILED_LOGIN_THRESHOLD}")
print("Failed login window: 5 minutes")


# ============================================================
# DETECTION 1
# MULTIPLE FAILED LOGIN ATTEMPTS
# ============================================================

print("\n[1] MULTIPLE FAILED LOGIN DETECTION")
print("-" * 65)

for username, failures in failed_logins.items():

    if len(failures) >= FAILED_LOGIN_THRESHOLD:

        print(
            f"[ALERT] {username} had "
            f"{len(failures)} failed login attempts."
        )


# ============================================================
# DETECTION 2
# FAILED LOGINS FOLLOWED BY SUCCESS
# WITHIN A TIME WINDOW
# ============================================================

print("\n[2] FAILED LOGINS FOLLOWED BY SUCCESS")
print("-" * 65)

for username, successes in successful_logins.items():

    failures = failed_logins.get(username, [])

    if not failures:
        continue

    for success in successes:

        window_start = (
            success["datetime"] - FAILED_LOGIN_WINDOW
        )

        recent_failures = [
            failure
            for failure in failures
            if window_start <= failure["datetime"]
            < success["datetime"]
        ]

        if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

            print(
                f"[ALERT] {username}: "
                f"{len(recent_failures)} failed logins "
                f"followed by a successful login at "
                f"{success['time']}."
            )


# ============================================================
# DETECTION 3
# UNUSUAL LOGIN HOURS
# ============================================================

print("\n[3] UNUSUAL LOGIN TIME DETECTION")
print("-" * 65)

for event in events:

    hour = event["datetime"].hour

    if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:

        print(
            f"[ALERT] {event['username']} logged in at "
            f"{event['time']} from {event['source_ip']}."
        )


# ============================================================
# DETECTION 4
# MULTIPLE SOURCE IP ADDRESSES
# ============================================================

print("\n[4] MULTIPLE SOURCE IP DETECTION")
print("-" * 65)

for username, ips in source_ips.items():

    if len(ips) > 1:

        print(
            f"[ALERT] {username} authenticated from "
            f"{len(ips)} different IP addresses:"
        )

        for ip in sorted(ips):
            print(f"        - {ip}")


# ============================================================
# DETECTION 5
# PRIVILEGED ACCOUNT ACTIVITY
# ============================================================

print("\n[5] PRIVILEGED ACCOUNT ACTIVITY")
print("-" * 65)

privileged_accounts_lower = {
    account.lower()
    for account in PRIVILEGED_ACCOUNTS
}

for event in events:

    username = event["username"]

    if username.lower() in privileged_accounts_lower:

        print(
            f"[INFO] {username} | "
            f"Event {event['event_id']} | "
            f"{event['time']} | "
            f"{event['source_ip']}"
        )


# ============================================================
# DETECTION 6
# RISK SCORING
# ============================================================

print("\n[6] RISK SCORING")
print("-" * 65)

risk_scores = defaultdict(int)
risk_reasons = defaultdict(list)


# ------------------------------------------------------------
# Indicator 1: Multiple failed logins
# ------------------------------------------------------------

for username, failures in failed_logins.items():

    if len(failures) >= FAILED_LOGIN_THRESHOLD:

        risk_scores[username] += 30

        risk_reasons[username].append(
            "multiple failed login attempts"
        )


# ------------------------------------------------------------
# Indicator 2: Failed logins followed by success
# ------------------------------------------------------------

for username, successes in successful_logins.items():

    failures = failed_logins.get(username, [])

    for success in successes:

        window_start = (
            success["datetime"] - FAILED_LOGIN_WINDOW
        )

        recent_failures = [
            failure
            for failure in failures
            if window_start <= failure["datetime"]
            < success["datetime"]
        ]

        if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

            risk_scores[username] += 30

            risk_reasons[username].append(
                "failed logins followed by successful login"
            )

            break


# ------------------------------------------------------------
# Indicator 3: Multiple source IP addresses
# ------------------------------------------------------------

for username, ips in source_ips.items():

    if len(ips) > 1:

        risk_scores[username] += 20

        risk_reasons[username].append(
            "authentication from multiple source IPs"
        )


# ------------------------------------------------------------
# Indicator 4: Unusual login hours
# ------------------------------------------------------------

unusual_time_users = set()

for event in events:

    hour = event["datetime"].hour

    if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:

        unusual_time_users.add(event["username"])


for username in unusual_time_users:

    risk_scores[username] += 10

    risk_reasons[username].append(
        "login outside normal working hours"
    )


# ------------------------------------------------------------
# Indicator 5: Privileged account
# ------------------------------------------------------------

for username in list(risk_scores.keys()):

    if username.lower() in privileged_accounts_lower:

        risk_scores[username] += 20

        risk_reasons[username].append(
            "privileged account activity"
        )


# ============================================================
# DISPLAY RISK SCORES
# ============================================================

print("\nRisk assessment:")

if not risk_scores:

    print("No suspicious authentication patterns detected.")

else:

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
            f"\n{username}"
            f"\n  Risk Score: {score}"
            f"\n  Severity: {severity}"
        )

        print("  Indicators:")

        for reason in dict.fromkeys(risk_reasons[username]):
            print(f"    - {reason}")


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

print("\n" + "=" * 65)
print("INVESTIGATION SUMMARY")
print("=" * 65)

if not risk_scores:

    print("\nNo accounts require further investigation.")

else:

    for username, score in sorted(
        risk_scores.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(f"\nAccount: {username}")
        print(f"Risk score: {score}")

        print(
            "Source IPs: "
            + ", ".join(sorted(source_ips[username]))
        )

        print(
            "Failed logins: "
            + str(len(failed_logins.get(username, [])))
        )

        print(
            "Successful logins: "
            + str(len(successful_logins.get(username, [])))
        )

        print("Investigation indicators:")

        for reason in dict.fromkeys(risk_reasons[username]):
            print(f"  - {reason}")


# ============================================================
# COMPLETION
# ============================================================

print("\nAnalysis complete.")
