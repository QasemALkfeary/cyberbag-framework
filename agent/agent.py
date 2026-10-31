"""
CyberBag Windows Agent

Single-file agent that runs on a Windows 10 endpoint.

Lifecycle:
  1. REGISTER   — Announce ourselves to the server, receive an agent ID.
  2. BEACON     — Poll the server every N seconds for pending tasks.
  3. EXECUTE    — When a task arrives, run the command via subprocess.
  4. REPORT     — POST execution results back to the server.
  5. TELEMETRY  — Collect Windows Security Event Logs AND Sysmon logs
                  within a time window around execution and POST them
                  to the server.
  6. LOOP       — Return to step 2.

Error handling strategy:
  - Network errors    → log warning, retry on next beacon cycle (never crash).
  - Registration fail → retry up to MAX_REGISTER_RETRIES, then exit.
  - Execution errors  → capture stderr/exit_code, report them as a normal result.
  - Server 4xx/5xx   → log warning, continue beacon loop.

Usage:
    python agent.py                           (uses defaults)
    python agent.py --server http://10.0.0.1:8888  (custom server)
"""

import argparse
import ctypes
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration (defaults, overridable via CLI args)
# ---------------------------------------------------------------------------
DEFAULT_SERVER_URL = "http://127.0.0.1:8888"
BEACON_INTERVAL = 5          # seconds between beacon calls
MAX_REGISTER_RETRIES = 5     # give up after this many failed registration attempts
REGISTER_RETRY_DELAY = 3     # seconds between registration retries
TELEMETRY_PRE_WINDOW = 2     # seconds before execution to capture
TELEMETRY_POST_WAIT = 3      # seconds to wait after execution for logs to flush
TELEMETRY_POST_WINDOW = 10   # seconds after execution to capture
SYSMON_EVENT_IDS = [1, 3, 10, 13]  # Process create, Network conn, Process access, Registry mod


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _log(level: str, message: str) -> None:
    """Structured console log with timestamp."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level.upper():5s}] {message}")


def _utc_to_local(utc_dt: datetime) -> datetime:
    """Convert a UTC datetime to the local system timezone."""
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)


def _is_admin() -> bool:
    """Check if the agent is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Not on Windows (shouldn't happen, but don't crash)
        return False


def _get_local_ip() -> str:
    """Best-effort local IP detection."""
    try:
        # Connect to a non-routable address to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Server Communication
# ---------------------------------------------------------------------------

def register(server_url: str) -> str:
    """
    Register this agent with the CyberBag server.

    Retries up to MAX_REGISTER_RETRIES times on failure.
    Returns the assigned agent ID on success.
    Exits the process if registration fails permanently.
    """
    url = f"{server_url}/api/agents/register"
    payload = {
        "hostname": socket.gethostname(),
        "ip_address": _get_local_ip(),
        "platform": platform.system().lower(),
    }

    for attempt in range(1, MAX_REGISTER_RETRIES + 1):
        try:
            _log("info", f"Registering with server (attempt {attempt}/{MAX_REGISTER_RETRIES})...")
            resp = requests.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            agent_data = resp.json()
            agent_id = agent_data["id"]
            _log("info", f"Registered successfully. Agent ID: {agent_id}")
            return agent_id
        except requests.ConnectionError:
            _log("warn", f"Cannot reach server at {server_url}")
        except requests.Timeout:
            _log("warn", "Registration request timed out")
        except requests.HTTPError as e:
            _log("error", f"Server rejected registration: {e}")
        except Exception as e:
            _log("error", f"Unexpected error during registration: {e}")

        if attempt < MAX_REGISTER_RETRIES:
            _log("info", f"Retrying in {REGISTER_RETRY_DELAY}s...")
            time.sleep(REGISTER_RETRY_DELAY)

    _log("error", "Registration failed after all retries. Exiting.")
    sys.exit(1)


def beacon(server_url: str, agent_id: str) -> dict:
    """
    Send a heartbeat to the server and check for pending work.

    Returns a dict with keys 'task' and 'baseline' (either or both may be None).
    On any error, returns {'task': None, 'baseline': None} so the loop retries.
    """
    url = f"{server_url}/api/agents/{agent_id}/beacon"
    empty = {"task": None, "baseline": None}
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {"task": data.get("task"), "baseline": data.get("baseline")}
    except requests.ConnectionError:
        _log("warn", "Lost connection to server (beacon)")
        return empty
    except requests.Timeout:
        _log("warn", "Beacon request timed out")
        return empty
    except requests.HTTPError as e:
        _log("warn", f"Beacon error: {e}")
        return empty
    except Exception as e:
        _log("error", f"Unexpected beacon error: {e}")
        return empty


def execute_task(task: dict) -> dict:
    """
    Execute the command from a task payload.

    Args:
        task: dict with keys 'task_id', 'command', 'executor'

    Returns:
        dict with keys 'stdout', 'stderr', 'exit_code', 'executed_at'
    """
    command = task["command"]
    executor = task["executor"]
    task_id = task["task_id"]

    _log("info", f"Executing task {task_id[:8]}...")
    _log("info", f"  Executor: {executor}")
    _log("info", f"  Command:  {command}")

    # Record timestamp immediately before execution
    executed_at = _utc_now()

    try:
        if executor == "powershell":
            full_command = ["powershell.exe", "-Command", command]
        else:
            # Default: cmd
            full_command = ["cmd.exe", "/c", command]

        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=60,
        )

        _log("info", f"  Exit code: {result.returncode}")
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "executed_at": executed_at,
        }
    except subprocess.TimeoutExpired:
        _log("warn", f"  Command timed out after 60s")
        return {
            "stdout": "",
            "stderr": "AGENT ERROR: Command timed out after 60 seconds",
            "exit_code": -1,
            "executed_at": executed_at,
        }
    except Exception as e:
        _log("error", f"  Execution failed: {e}")
        return {
            "stdout": "",
            "stderr": f"AGENT ERROR: {e}",
            "exit_code": -1,
            "executed_at": executed_at,
        }


def report_result(server_url: str, task_id: str, result: dict) -> bool:
    """
    POST execution results back to the server.

    Returns True if the server accepted the result, False otherwise.
    On failure, the result is lost (acceptable for MVP — the task
    will remain in 'sent' state on the server, which is observable).
    """
    url = f"{server_url}/api/tasks/{task_id}/result"
    try:
        resp = requests.post(url, json=result, timeout=10)
        resp.raise_for_status()
        _log("info", f"Result reported for task {task_id[:8]}...")
        return True
    except requests.ConnectionError:
        _log("warn", "Lost connection to server (report)")
        return False
    except requests.HTTPError as e:
        _log("warn", f"Server rejected result: {e}")
        return False
    except Exception as e:
        _log("error", f"Unexpected error reporting result: {e}")
        return False


# ---------------------------------------------------------------------------
# Telemetry Collection
# ---------------------------------------------------------------------------

def collect_security_logs(executed_at_str: str) -> list[dict]:
    """
    Collect Windows Security Event Logs (with built-in wait).

    Legacy entry point — waits for log flush then collects.
    Prefer collect_telemetry() which collects all sources with a single wait.
    """
    if os.name != "nt":
        _log("warn", "Telemetry collection skipped (not Windows)")
        return []

    _log("info", f"Waiting {TELEMETRY_POST_WAIT}s for log flush...")
    time.sleep(TELEMETRY_POST_WAIT)
    return _collect_security_logs_no_wait(executed_at_str)


def _collect_security_logs_no_wait(executed_at_str: str) -> list[dict]:
    """
    Collect Windows Security Event Logs within a time window around execution.

    Does NOT wait for log flush — caller is responsible for waiting.

    Returns a list of dicts, each with: source, event_id, timestamp, raw_data.
    Returns empty list on any failure (non-admin, no events, errors).
    """
    if os.name != "nt":
        return []

    # Parse executed_at (UTC) and convert to local time for PowerShell query.
    # Get-WinEvent -FilterHashtable StartTime/EndTime are local-time values.
    try:
        exec_time = datetime.fromisoformat(executed_at_str)
        local_time = _utc_to_local(exec_time)
    except ValueError:
        _log("error", f"Cannot parse executed_at: {executed_at_str}")
        return []

    window_start = local_time - timedelta(seconds=TELEMETRY_PRE_WINDOW)
    window_end = local_time + timedelta(seconds=TELEMETRY_POST_WINDOW)

    # Format for PowerShell: yyyy-MM-ddTHH:mm:ss (local time)
    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S")

    _log("info", f"Collecting Security logs [{start_str} to {end_str}] (local time)")

    # PowerShell script that:
    # 1. Queries Security log within the time window
    # 2. Selects relevant fields
    # 3. Outputs as JSON array
    ps_script = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "$events = Get-WinEvent -FilterHashtable @{"
        "  LogName='Security';"
        f"  StartTime='{start_str}';"
        f"  EndTime='{end_str}'"
        "} -MaxEvents 50; "
        "if ($events) {"
        "  $events | ForEach-Object {"
        "    [PSCustomObject]@{"
        "      EventId = $_.Id;"
        "      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o');"
        "      Message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500));"
        "      ProviderName = $_.ProviderName"
        "    }"
        "  } | ConvertTo-Json -Compress"
        "} else { '[]' }"
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            _log("warn", f"PowerShell returned exit code {result.returncode}")
            if "Access" in result.stderr or "privilege" in result.stderr.lower():
                _log("warn", "Insufficient privileges to read Security log")
            return []

        raw_output = result.stdout.strip()
        if not raw_output or raw_output == "[]":
            _log("info", "No Security events found in window")
            return []

        # Parse JSON — PowerShell returns object (not array) for single event
        parsed = json.loads(raw_output)
        if isinstance(parsed, dict):
            parsed = [parsed]

        events = []
        for evt in parsed:
            events.append({
                "source": "security_event_log",
                "event_id": evt.get("EventId", 0),
                "timestamp": evt.get("TimeCreated", ""),
                "raw_data": json.dumps(evt),
            })

        _log("info", f"Collected {len(events)} Security event(s)")
        return events

    except subprocess.TimeoutExpired:
        _log("warn", "Telemetry collection timed out")
        return []
    except json.JSONDecodeError as e:
        _log("warn", f"Failed to parse telemetry JSON: {e}")
        return []
    except Exception as e:
        _log("error", f"Telemetry collection failed: {e}")
        return []


def collect_sysmon_logs(executed_at_str: str) -> list[dict]:
    """
    Collect Sysmon events from the Microsoft-Windows-Sysmon/Operational log
    within the same time window used for Security logs.

    Targets high-value Sysmon events:
      Event 1  — Process creation (detailed command line, hashes, parent process)
      Event 3  — Network connection (source/dest IP, port, process)
      Event 10 — Process access (e.g. LSASS credential dumping detection)
      Event 13 — Registry value set (persistence via Run keys, etc.)

    Returns a list of dicts with: source, event_id, timestamp, raw_data.
    Returns empty list on any failure (Sysmon not installed, no events, errors).
    """
    if os.name != "nt":
        return []

    # Parse executed_at (UTC) and convert to local time for PowerShell query.
    # Get-WinEvent -FilterHashtable StartTime/EndTime are local-time values.
    try:
        exec_time = datetime.fromisoformat(executed_at_str)
        local_time = _utc_to_local(exec_time)
    except ValueError:
        _log("error", f"Cannot parse executed_at for Sysmon: {executed_at_str}")
        return []

    window_start = local_time - timedelta(seconds=TELEMETRY_PRE_WINDOW)
    window_end = local_time + timedelta(seconds=TELEMETRY_POST_WINDOW)

    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S")

    # Build comma-separated ID list for PowerShell array
    id_list = ",".join(str(eid) for eid in SYSMON_EVENT_IDS)

    _log("info", f"Collecting Sysmon logs [{start_str} to {end_str}] IDs: {id_list}")

    ps_script = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "$events = Get-WinEvent -FilterHashtable @{"
        "  LogName='Microsoft-Windows-Sysmon/Operational';"
        f"  Id=@({id_list});"
        f"  StartTime='{start_str}';"
        f"  EndTime='{end_str}'"
        "} -MaxEvents 50; "
        "if ($events) {"
        "  $events | ForEach-Object {"
        "    [PSCustomObject]@{"
        "      EventId = $_.Id;"
        "      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o');"
        "      Message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500));"
        "      ProviderName = $_.ProviderName"
        "    }"
        "  } | ConvertTo-Json -Compress"
        "} else { '[]' }"
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            _log("warn", f"Sysmon PowerShell returned exit code {result.returncode}")
            if "no events" in result.stderr.lower() or "not found" in result.stderr.lower():
                _log("warn", "Sysmon log not available (Sysmon may not be installed)")
            return []

        raw_output = result.stdout.strip()
        if not raw_output or raw_output == "[]":
            _log("info", "No Sysmon events found in window")
            return []

        parsed = json.loads(raw_output)
        if isinstance(parsed, dict):
            parsed = [parsed]

        events = []
        for evt in parsed:
            events.append({
                "source": "sysmon",
                "event_id": evt.get("EventId", 0),
                "timestamp": evt.get("TimeCreated", ""),
                "raw_data": json.dumps(evt),
            })

        _log("info", f"Collected {len(events)} Sysmon event(s)")
        return events

    except subprocess.TimeoutExpired:
        _log("warn", "Sysmon telemetry collection timed out")
        return []
    except json.JSONDecodeError as e:
        _log("warn", f"Failed to parse Sysmon JSON: {e}")
        return []
    except Exception as e:
        _log("error", f"Sysmon telemetry collection failed: {e}")
        return []


def collect_telemetry(executed_at_str: str) -> list[dict]:
    """
    Collect telemetry from all supported sources:
      1. Windows Security Event Log
      2. Sysmon (Microsoft-Windows-Sysmon/Operational)

    Waits once for log flush, then queries both sources.
    Returns combined list of events.
    """
    if os.name != "nt":
        _log("warn", "Telemetry collection skipped (not Windows)")
        return []

    _log("info", f"Waiting {TELEMETRY_POST_WAIT}s for log flush...")
    time.sleep(TELEMETRY_POST_WAIT)

    # Collect from both sources (Security log wait is handled here, not inside)
    security_events = _collect_security_logs_no_wait(executed_at_str)
    sysmon_events = collect_sysmon_logs(executed_at_str)

    combined = security_events + sysmon_events
    _log("info", f"Total telemetry: {len(combined)} event(s) "
         f"(Security: {len(security_events)}, Sysmon: {len(sysmon_events)})")
    return combined


def _collect_events_in_window(window_start_iso: str, window_end_iso: str) -> list[dict]:
    """Collect Security + Sysmon events whose timestamps fall in [start, end].

    Reuses the single-source collectors by centering each call on the
    midpoint and widening the pre/post windows to span the full range.
    Used exclusively by baseline mode.
    """
    if os.name != "nt":
        _log("warn", "Baseline collection skipped (not Windows)")
        return []

    try:
        start = datetime.fromisoformat(window_start_iso)
        end = datetime.fromisoformat(window_end_iso)
    except ValueError:
        _log("error", f"Bad baseline window: {window_start_iso} .. {window_end_iso}")
        return []

    # Convert to local time for Get-WinEvent, which expects local-time values.
    local_start = _utc_to_local(start)
    local_end = _utc_to_local(end)
    start_str = local_start.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = local_end.strftime("%Y-%m-%dT%H:%M:%S")
    _log("info", f"Baseline window [{start_str} .. {end_str}] (local)")

    def _collect(log_name: str, id_filter: Optional[str], source_tag: str) -> list[dict]:
        id_clause = f"Id=@({id_filter});" if id_filter else ""
        ps_script = (
            "$ErrorActionPreference = 'SilentlyContinue'; "
            "$events = Get-WinEvent -FilterHashtable @{"
            f"  LogName='{log_name}';"
            f"  {id_clause}"
            f"  StartTime='{start_str}';"
            f"  EndTime='{end_str}'"
            "} -MaxEvents 500; "
            "if ($events) {"
            "  $events | ForEach-Object {"
            "    [PSCustomObject]@{"
            "      EventId = $_.Id;"
            "      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o');"
            "      Message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500));"
            "      ProviderName = $_.ProviderName"
            "    }"
            "  } | ConvertTo-Json -Compress"
            "} else { '[]' }"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                return []
            raw = result.stdout.strip()
            if not raw or raw == "[]":
                return []
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            return [{
                "source": source_tag,
                "event_id": evt.get("EventId", 0),
                "timestamp": evt.get("TimeCreated", ""),
                "raw_data": json.dumps(evt),
            } for evt in parsed]
        except Exception as exc:
            _log("warn", f"Baseline collect from {log_name} failed: {exc}")
            return []

    security = _collect("Security", None, "security_event_log")
    sysmon = _collect(
        "Microsoft-Windows-Sysmon/Operational",
        ",".join(str(eid) for eid in SYSMON_EVENT_IDS),
        "sysmon",
    )
    total = security + sysmon
    _log(
        "info",
        f"Baseline collected {len(total)} event(s) "
        f"(Security: {len(security)}, Sysmon: {len(sysmon)})",
    )
    return total


def submit_baseline_events(
    server_url: str,
    run_id: str,
    window_start: str,
    window_end: str,
    events: list[dict],
) -> bool:
    """POST collected baseline events for a specific window."""
    url = f"{server_url}/api/baseline/{run_id}/events"
    payload = {
        "window_start": window_start,
        "window_end": window_end,
        "events": events,
    }
    try:
        resp = requests.post(url, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _log(
            "info",
            f"Baseline chunk accepted: {data.get('accepted', 0)} event(s), "
            f"run status={data.get('status')}",
        )
        return True
    except requests.ConnectionError:
        _log("warn", "Lost connection to server (baseline)")
        return False
    except requests.HTTPError as e:
        _log("warn", f"Server rejected baseline events: {e}")
        return False
    except Exception as e:
        _log("error", f"Unexpected baseline error: {e}")
        return False


def report_telemetry(server_url: str, task_id: str, events: list[dict]) -> bool:
    """
    POST collected telemetry events to the server.

    Returns True on success, False on failure.
    Failure is non-fatal — the task result is already stored.
    """
    if not events:
        return True  # nothing to send

    url = f"{server_url}/api/tasks/{task_id}/telemetry"
    try:
        resp = requests.post(url, json={"events": events}, timeout=10)
        resp.raise_for_status()
        _log("info", f"Telemetry reported: {len(events)} event(s) for task {task_id[:8]}...")
        return True
    except requests.ConnectionError:
        _log("warn", "Lost connection to server (telemetry)")
        return False
    except requests.HTTPError as e:
        _log("warn", f"Server rejected telemetry: {e}")
        return False
    except Exception as e:
        _log("error", f"Unexpected telemetry error: {e}")
        return False


# ---------------------------------------------------------------------------
# Main Loop
# ---------------------------------------------------------------------------

def main(server_url: str) -> None:
    """
    Agent main loop.

    State machine:
      REGISTER → BEACON → (no task? sleep) → BEACON
                         → (task? EXECUTE → REPORT) → BEACON
    """
    _log("info", "=" * 50)
    _log("info", "CyberBag Windows Agent starting")
    _log("info", f"Server: {server_url}")
    _log("info", f"Host:   {socket.gethostname()}")
    _log("info", f"IP:     {_get_local_ip()}")

    # Warn if not running as admin (won't block — telemetry collection needs it later)
    if os.name == "nt" and not _is_admin():
        _log("warn", "Not running as Administrator. Telemetry collection will fail later.")

    _log("info", "=" * 50)

    # --- Phase 1: Register ---
    agent_id = register(server_url)

    # --- Phase 2: Beacon loop ---
    _log("info", f"Entering beacon loop (interval: {BEACON_INTERVAL}s)")

    while True:
        directive = beacon(server_url, agent_id)
        task = directive.get("task")
        baseline_directive = directive.get("baseline")

        if task is not None:
            # --- Attack mode: execute task, report result + telemetry ---
            result = execute_task(task)
            report_result(server_url, task["task_id"], result)
            telemetry = collect_telemetry(result["executed_at"])
            report_telemetry(server_url, task["task_id"], telemetry)
        elif baseline_directive is not None:
            # --- Baseline mode: collect the server-assigned window ---
            run_id = baseline_directive["run_id"]
            win_start = baseline_directive["window_start"]
            win_end = baseline_directive["window_end"]
            _log("info", f"Baseline run {run_id[:8]} — collecting window")
            events = _collect_events_in_window(win_start, win_end)
            submit_baseline_events(server_url, run_id, win_start, win_end, events)
        else:
            _log("info", "No work. Sleeping...")

        time.sleep(BEACON_INTERVAL)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberBag Windows Agent")
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER_URL,
        help=f"CyberBag server URL (default: {DEFAULT_SERVER_URL})",
    )
    args = parser.parse_args()
    try:
        main(args.server)
    except KeyboardInterrupt:
        _log("info", "Agent stopped by user.")
