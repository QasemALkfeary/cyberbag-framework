"""Test the 3 fixed PowerShell commands using the same subprocess pattern as the agent."""
import subprocess

def test_command(name, command):
    """Simulate agent execution: ['powershell.exe', '-Command', command]"""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"Command: {command[:100]}...")

    # This is exactly what the agent does for executor="powershell"
    full_command = ["powershell.exe", "-Command", command]

    try:
        result = subprocess.run(full_command, capture_output=True, text=True, timeout=15)
        print(f"Exit code: {result.returncode}")
        print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr[:300]}")
        return result.returncode == 0
    except Exception as e:
        print(f"ERROR: {e}")
        return False

# T1057.EDR — avoid double-nesting, just raw PS code
# Since agent does ["powershell.exe", "-Command", command],
# and command starts with "powershell.exe -Command ...", we get double nesting.
# The outer PS expands $variables in "..." before passing to inner PS.
# Fix: use backtick-escaped $ so outer PS preserves them.

# Actually let's first test: what if command does NOT start with powershell.exe?
# Agent code: full_command = ["powershell.exe", "-Command", command]
# If command = "Get-Process | ...", then PS runs it directly. No double nesting.
# But ALL existing abilities use "powershell.exe -Command ..." format.
# The ones that work have no $ in the double-quoted section.

# Let's test the double-nesting with backtick-escaped $
test_command(
    "T1016.DOM (backtick escape)",
    'powershell.exe -Command "`$cs=Get-CimInstance Win32_ComputerSystem; Write-Output (`$cs.Name); Write-Output (`$cs.Domain); Write-Output (`$cs.PartOfDomain)"'
)

# Test with single-quoted wrapper (no variable expansion)
test_command(
    "T1016.DOM (single-quote wrapper)",
    "powershell.exe -Command '$cs=Get-CimInstance Win32_ComputerSystem; Write-Output $cs.Name; Write-Output $cs.Domain; Write-Output $cs.PartOfDomain'"
)

# Test without double-nesting at all - just raw PS code
test_command(
    "T1016.DOM (no double-nest)",
    "$cs=Get-CimInstance Win32_ComputerSystem; Write-Output ('Hostname: '+$cs.Name); Write-Output ('Domain: '+$cs.Domain); Write-Output ('PartOfDomain: '+[string]$cs.PartOfDomain)"
)

# Test T1033.PRIV without double-nesting
test_command(
    "T1033.PRIV (no double-nest)",
    "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($i); $a=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); $g=whoami /groups 2>$null | Select-String 'Mandatory Label'; Write-Output ('User: '+$i.Name); Write-Output ('IsAdmin: '+[string]$a); Write-Output ('IntegrityLevel: '+$g)"
)

# Test T1057.EDR without double-nesting
test_command(
    "T1057.EDR (no double-nest)",
    "$p = Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match 'MsMpEng|cb|CylanceSvc|CSFalcon|SentinelAgent|elastic-agent|winlogbeat|ossec|Tanium|CrowdStrike|bdservicehost'}; if($p){$p | Select-Object ProcessName,Id | Format-Table -AutoSize}else{Write-Output ''}"
)
