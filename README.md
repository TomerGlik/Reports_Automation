# 🔐 BruteForce VPN Report → Feeder Ingestion

Ingests daily VPN brute-force report CSVs from a date-stamped folder tree, filters IPs by exclusion rules, and appends de-duplicated results into feeder files.  
Writes simple TXT logs (per-IP, per-run, and a capped debug log).

> **Target OS:** 🪟 Windows  
> **Python:** 🐍 3.9+  
> **CSV headers required:** `ip.dst`, `user.dst`

---

## ✨ Features
- 📂 Scans `C:\Reports\YYYYMMDD\<SECOND_LEVEL_DIR>\**\*.csv`
- 🔎 Filename match is tolerant (case/extra-spaces) and falls back to **header-based** detection
- ✅ Validates IPv4 addresses
- 🚫 Excludes users:
  - starting with `dmz-hct\` (any case; any number of backslashes)
  - starting with `dmz\` (any case; any number of backslashes)
  - matching `first.last` (ASCII letters only)
- 🔄 Skips duplicates and excluded IPs
- 📄 Outputs:
  - `ip.txt` — one IP per line
  - `ip.csv` — `ip,ip_hct_blacklist`
- 📝 Logs:
  - `ip_TimeLog.txt` — `[YYYY-MM-DD] <ip>  Made by: Automation.`
  - `BruteForce_Auto_TimeLog.txt` — `[YYYY-MM-DD] Inserted <N> IPs`
  - `BruteForce_Debug.txt` — capped to last **300** lines

---

## ⚙️ Configuration
At the top of the script, set the **constants**:

```python
REPORTS_ROOT = Path(r"C:\your\reports\path")      # root that contains YYYYMMDD folders
SECOND_LEVEL_DIR = "Report_Subdir"                # subfolder under YYYYMMDD
TARGET_CSV_BASENAME = "Report_Name"               # expected report name (no extension)
FEEDER_DIR = Path(r"C:\your\feeder\path")         # feeder dir (ip.txt/ip.csv/logs)

EXCLUDED_TXT = FEEDER_DIR / "excluded_ips.txt"
IP_TXT = FEEDER_DIR / "ip.txt"
IP_CSV = FEEDER_DIR / "ip.csv"
MAX_DEBUG_LINES = 300

LOGS_DIR     = FEEDER_DIR / "Logs"
IP_TIMELOG   = LOGS_DIR / "ip_TimeLog.txt"
AUTO_TIMELOG = LOGS_DIR / "BruteForce_Auto_TimeLog.txt"
DEBUG_LOG    = LOGS_DIR / "BruteForce_Debug.txt"
```
## 📊 How it works

## 📅 Resolve the target date folder (default = yesterday).
Override with --date YYYYMMDD.
Use --fallback-latest if the folder is missing.

## 📑 Collect candidate CSVs → filename match OR fallback to header-based detection.

## 🧹 Validate rows:

IPv4 format

Skip if in excluded_ips.txt or ip.txt

Skip if username matches exclusion rules

## 🖊️ Append unique IPs to:

ip.txt

ip.csv

## 📝 Log activity into 3 logs (per-IP, per-run, debug).

  default run (yesterday's folder)
  python BruteForceVPNReport.py

   specific date
  python BruteForceVPNReport.py --date 20250904

  fallback to latest available folder if missing
  python BruteForceVPNReport.py --fallback-latest

## ⏰ Scheduling (Windows Task Scheduler)

schtasks /Create /TN "BruteForceFeeder" /TR "C:\Path\To\Python\python.exe C:\Path\To\BruteForceVPNReport.py" /SC DAILY /ST 03:00 /RL HIGHEST

## 📚 Logs Overview

🗂️ ip_TimeLog.txt: one line per inserted IP
      [2025-09-05] 1.2.3.4  Made by: Automation.
📅 BruteForce_Auto_TimeLog.txt: one line per run
      [2025-09-05] Inserted 7 IPs
🐞 BruteForce_Debug.txt: chronological trace, capped to 300 lines (oldest dropped first).

## 🛠 Troubleshooting
  ❌ No matching CSV files → check REPORTS_ROOT, SECOND_LEVEL_DIR, and filename vs TARGET_CSV_BASENAME.

  🔄 IPs not inserted → maybe already exist in ip.txt, in excluded_ips.txt, or skipped by user rules.

  ⚠️ Encoding errors → adjust encodings (utf-8-sig, cp1255, utf-8).
