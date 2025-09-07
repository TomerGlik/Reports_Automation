import argparse
import csv
import ipaddress
import re
from datetime import date, datetime, timedelta
from pathlib import Path

# ---- Constants ----
REPORTS_ROOT = Path(r"C:\your\reports\path")
SECOND_LEVEL_DIR = ""
TARGET_CSV_BASENAME = "Report_Name"  # name without extension
REQUIRED_COLS = ("ip.dst", "user.dst")

FEEDER_DIR = Path(r"C:\your\feeder\path")
EXCLUDED_TXT = FEEDER_DIR / "excluded_ips.txt"
IP_TXT = FEEDER_DIR / "ip.txt"
IP_CSV = FEEDER_DIR / "ip.csv"
MAX_DEBUG_LINES = 300

LOGS_DIR = FEEDER_DIR / "your\logs\path"
IP_TIMELOG = LOGS_DIR / "your\logs\path"   # Each line: [YYYY-MM-DD] <ip> Made by: Automation.
AUTO_TIMELOG = LOGS_DIR / "your\logs\path" #[YYYY-MM-DD] Inserted <N> IPs
DEBUG_LOG = LOGS_DIR / "your\logs\path" #Debugging


# ---- Helpers & validations ----
def is_valid_ipv4(ip: str) -> bool:
    """Return True if 'ip' is a syntactically valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except Exception:
        return False


def user_is_excluded(user: str) -> bool:
    """
    Exclusion rules:
    - Starts with 'domain' (case-insensitive)
    - Username in 'first.last' format (ASCII letters only), e.g., 'tomer.glik'
    """
    if not user:
        return False
    u = user.strip().lower()
    while "\\\\" in u:
        u=u.replace("\\\\", "\\")
    if u.startswith("domain\\") or u.startswith(r"domain\\"):
        return True
    return False


def read_set_from_txt(path: Path) -> set[str]:
    """Load a text file into a set of non-empty, stripped lines."""
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.strip()}


def load_existing_ip_txt() -> set[str]:
    """Load current ip.txt values into a set."""
    return read_set_from_txt(IP_TXT)


def load_excluded_ips() -> set[str]:
    """Load excluded_ips.txt into a set."""
    return read_set_from_txt(EXCLUDED_TXT)

def dbg(line: str):
    """Append a single debug line into BruteForce_debug.txt with timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_line = f"[{ts}] {line}\n"
    try:
        with DEBUG_LOG.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    if len(lines) < MAX_DEBUG_LINES:
        with DEBUG_LOG.open("a", encoding="utf-8", newline="\n") as f:
            f.write(new_line)
    else:
        lines = lines[1:] #Delete the old
        lines.append(new_line)
        with DEBUG_LOG.open("w", encoding="utf-8", newline="\n") as f:
            f.writeline(lines)


def ensure_paths():
    """Ensure feeder directory, logs directory, and required files exist."""
    FEEDER_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    for p in (EXCLUDED_TXT, IP_TXT, IP_CSV, IP_TIMELOG, AUTO_TIMELOG, DEBUG_LOG):
        if not p.exists():
            p.touch()


def sniff_reader(fobj):
    """Try to detect CSV dialect and return a DictReader robust to BOM/encodings."""
    sample = fobj.read(4096)
    fobj.seek(0)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except Exception:
        dialect = csv.get_dialect("excel")
    return csv.DictReader(fobj, dialect=dialect)


def csv_has_required_columns(path: Path) -> bool:
    """Return True if the CSV file contains the required headers."""
    for enc in ("utf-8-sig", "cp1255", "utf-8"):
        try:
            with path.open("r", encoding=enc, errors="strict", newline="") as f:
                reader = sniff_reader(f)
                if not reader.fieldnames:
                    continue
                cols = {c.lower() for c in reader.fieldnames}
                if set(REQUIRED_COLS).issubset(cols):
                    return True
        except Exception:
            continue
    return False


def iter_csv_rows(csv_path: Path):
    """
    Yield tuples (ip, user, csv_path) from the CSV,
    trying a few encodings common on Windows.
    """
    for enc in ("utf-8-sig", "cp1255", "utf-8"):
        try:
            with csv_path.open("r", encoding=enc, errors="strict", newline="") as f:
                reader = sniff_reader(f)
                field_map = {name.lower(): name for name in (reader.fieldnames or [])}
                ip_key = field_map.get("ip.dst")
                user_key = field_map.get("user.dst")
                if not ip_key or not user_key:
                    raise ValueError(f"Missing columns in {csv_path} (require ip.dst and user.dst)")
                for row in reader:
                    yield (row.get(ip_key, "").strip(), row.get(user_key, "").strip(), csv_path)
            return
        except Exception:
            continue
    raise RuntimeError(f"Failed to read with known encodings: {csv_path}")


def normalize_name(s: str) -> str:
    """Normalize file base name: collapse spaces and lower-case."""
    return re.sub(r"\s+", " ", s).strip().lower()


def collect_target_csvs(base_dir: Path, debug: bool = False) -> list[Path]:
    """
    Find all CSVs under base_dir matching the target base name,
    case-insensitively and ignoring repeated spaces. Accept .csv/.CSV.
    If none found, fall back to any CSV under base_dir that contains
    the required headers (ip.dst,user.dst).
    """
    if debug:
        print(f"[DEBUG] Scanning under: {base_dir}")

    wanted = normalize_name(TARGET_CSV_BASENAME)
    candidates: list[Path] = []

    # Pass 1: name-based match (robust normalization)
    for p in base_dir.rglob("*.csv"):
        try:
            if normalize_name(p.stem) == wanted:
                candidates.append(p)
        except Exception:
            continue

    if not candidates:
        # Pass 2 (fallback): any CSV with the required columns
        if debug:
            print("[DEBUG] Name-based match failed, falling back to header-based detection")
        for p in base_dir.rglob("*.csv"):
            try:
                if csv_has_required_columns(p):
                    candidates.append(p)
            except Exception:
                continue

    if debug:
        print(f"[DEBUG] Found {len(candidates)} CSV files:")
        for c in candidates:
            print(f"        - {c}")

    return candidates


def append_lines(path: Path, lines: list[str]):
    """Append given lines to a text file (UTF-8, LF line endings)."""
    if not lines:
        return
    with path.open("a", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")


def append_log_lines(ips: list[str]):
    """
    Append IPs to the time log file with today's date:
    Format: [YYYY-MM-DD] <ip>
    """
    if not ips:
        return
    today_str = date.today().strftime("%Y-%m-%d")
    lines = [f"[{today_str}] {ip} Made by: Automation." for ip in ips]
    append_lines(IP_TIMELOG, lines)
def append_automation_run_log(inserted_count: int):
    """
    Log automation run summary:
    One Line: [YYYY-MM-DD] Inserted <N> IPs
    """
    today_str = date.today().strftime("%Y-%m-%d")
    line = f"[{today_str}] Inserted {inserted_count} IPs"
    append_lines(AUTO_TIMELOG, [line])


def today_str_yyyymmdd() -> str:
    """Return local system date before formatted as YYYYMMDD."""
    return (date.today()- timedelta(days=1)).strftime("%Y%m%d")


def latest_reports_folder() -> str | None:
    """
    Find the latest folder under REPORTS_ROOT whose name matches 8 digits (YYYYMMDD).
    Return its name (string) or None if not found.
    """
    if not REPORTS_ROOT.exists():
        return None
    candidates = []
    for p in REPORTS_ROOT.iterdir():
        if p.is_dir() and re.fullmatch(r"\d{8}", p.name):
            candidates.append(p.name)
    return max(candidates) if candidates else None


def resolve_date_folder(override_date: str | None, allow_fallback_latest: bool) -> str:
    """
    Resolve which YYYYMMDD folder to use.
    """
    if override_date:
        if not re.fullmatch(r"\d{8}", override_date):
            raise SystemExit("Invalid --date. Use YYYYMMDD, e.g., 20250904.")
        candidate = override_date
    else:
        candidate = today_str_yyyymmdd()

    base_dir = REPORTS_ROOT / candidate / SECOND_LEVEL_DIR
    if base_dir.exists():
        return candidate

    if allow_fallback_latest:
        latest = latest_reports_folder()
        if latest:
            print(f"Warning: folder for {candidate} not found. Falling back to latest: {latest}")
            return latest

    raise SystemExit(f"Base directory does not exist: {REPORTS_ROOT / candidate / SECOND_LEVEL_DIR}")


def process(date_yyyymmdd: str, debug: bool = False) -> None:
    """Main routine: filter IPs from CSVs and write outputs + time log."""
    dbg(f"Run started for = {date_yyyymmdd}")
    base_dir = REPORTS_ROOT / date_yyyymmdd / SECOND_LEVEL_DIR
    dbg(f"Base directory: {base_dir}")

    ensure_paths()

    excluded = load_excluded_ips()
    existing_ip_txt = load_existing_ip_txt()

    to_add_ip_txt: set[str] = set()
    to_add_ip_csv: set[str] = set()

    csv_files = collect_target_csvs(base_dir, debug=debug)
    if not csv_files:
        print(f"No matching CSV files under {base_dir}")
        return

    total_rows = 0
    kept_rows = 0
    skipped_reason_counts = {
        "bad_ip": 0,
        "in_excluded": 0,
        "already_in_ip_txt": 0,
        "user_excluded": 0,
        "duplicate_in_run": 0,
    }

    seen_in_run: set[str] = set()

    for csv_path in csv_files:
        for ip, user, _ in iter_csv_rows(csv_path):
            total_rows += 1

            # Validation pipeline
            if not is_valid_ipv4(ip):
                skipped_reason_counts["bad_ip"] += 1
                continue
            if ip in excluded:
                skipped_reason_counts["in_excluded"] += 1
                continue
            if ip in existing_ip_txt:
                skipped_reason_counts["already_in_ip_txt"] += 1
                continue
            if user_is_excluded(user):
                skipped_reason_counts["user_excluded"] += 1
                continue
            if ip in seen_in_run:
                skipped_reason_counts["duplicate_in_run"] += 1
                continue

            # Passed all checks
            seen_in_run.add(ip)
            kept_rows += 1
            dbg(f"ACCEPT ip={ip} user={user}")
            to_add_ip_txt.add(ip)
            to_add_ip_csv.add(f"{ip},csv_format")

    # Write outputs (sorted for stable diffs)
    sorted_ips = sorted(to_add_ip_txt)
    append_lines(IP_TXT, sorted_ips)
    append_lines(IP_CSV, sorted(to_add_ip_csv))
    append_log_lines(sorted_ips)  # time-stamped log entries
    append_automation_run_log(kept_rows)
    dbg(f"Inserted {kept_rows} new IPs skipped={skipped_reason_counts}")
    dbg("Run finished now come to the jaccuzi babe, we need to talk about your promotion")

    # Summary
    print(f"Scanned {total_rows} rows from {len(csv_files)} files.")
    print(f"Inserted {kept_rows} new IPs.")
    print("Skip reasons:", skipped_reason_counts)
    print(f"Wrote to: {IP_TXT}, {IP_CSV}, and logged to: {IP_TIMELOG}")


def main():
    # argparse for optional overrides; by default uses the server's local date
    parser = argparse.ArgumentParser(
        description="Ingest IPs into feeder from 'RSA-SSL VPN Generic Users Brute Force attempt' CSVs."
    )
    parser.add_argument("--date", help="Override date in YYYYMMDD.")
    parser.add_argument(
        "--fallback-latest",
        action="store_true",
        help="If today's/override folder is missing, fall back to the latest YYYYMMDD folder under C:\\Reports.",
    )
    parser.add_argument("--debug", action="store_true", help="Print debug info about discovered CSVs.")
    args = parser.parse_args()

    yyyymmdd = resolve_date_folder(args.date, args.fallback_latest)
    process(yyyymmdd, debug=args.debug)


if __name__ == "__main__":
    main()
