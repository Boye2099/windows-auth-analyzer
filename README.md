# Windows Authentication Analyzer

A small Python security project I built to practice analyzing Windows authentication logs and detecting suspicious login activity.

The project uses synthetic Windows authentication data and looks for patterns that could be worth investigating, such as repeated failed logins, unusual login times, and accounts being used from different IP addresses.

## What it does

The analyzer checks for:

* Multiple failed login attempts
* Failed logins followed by a successful login
* Login activity outside normal working hours
* Accounts being used from multiple IP addresses
* Activity from privileged accounts
* A simple risk score based on the findings

## Windows Events Used

The project currently works with two common Windows authentication events:

| Event ID | Description      |
| -------- | ---------------- |
| 4624     | Successful logon |
| 4625     | Failed logon     |

## How the detection works

For example, if an account has several failed logins and then successfully logs in within a few minutes, the tool flags the activity for investigation.

It also looks for things like:

```text
Multiple failed logins
        ↓
Successful login
        ↓
Different source IP
        ↓
Unusual login time
```

These indicators don't automatically mean an account has been compromised. They are signals that would need to be investigated with other security logs and context.

## Risk Scoring

The project gives points to accounts when certain indicators are found:

* Multiple failed logins: +30
* Failed logins followed by success: +30
* Multiple source IPs: +20
* Unusual login time: +10
* Privileged account activity: +20

The score is mainly used to help prioritize which accounts deserve a closer look.

## Project Structure

```text
windows-auth-analyzer/
├── auth_analyzer.py
├── auth_logs.csv
├── README.md
└── requirements.txt
```

## Running it

You only need Python installed.

```bash
python auth_analyzer.py
```

The script reads the `auth_logs.csv` file and prints the detected activity and risk scores.

## Example

A sequence like this:

```text
4625  Failed login
4625  Failed login
4625  Failed login
4624  Successful login
```

within a short period will be flagged by the analyzer.

## What I learned

This project helped me practice:

* Python log parsing
* Working with CSV data
* Windows Event IDs
* Authentication monitoring
* Detection logic
* Basic risk scoring
* Thinking through security alerts instead of treating every alert as an attack

## Limitations

This is a learning project using synthetic data.

The risk score is a simple model and isn't meant to prove that an account has been compromised. A real SOC environment would combine authentication logs with other information such as PowerShell activity, processes, network connections, logon types, and user/device baselines.

## Future Improvements

Some things I would like to add later:

* More Windows Event IDs
* Logon type analysis
* Support for larger log files
* JSON log support
* Better time-based detection
* Report generation
* More detailed investigation output
* SIEM integration

## Disclaimer

This project is for defensive security learning and uses synthetic authentication data.
