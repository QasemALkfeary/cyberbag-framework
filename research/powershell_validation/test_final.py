"""Final test of the 3 fixed commands exactly as they will be stored in DB."""
import subprocess

def test(name, cmd):
    r = subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True, text=True, timeout=15)
    print(f"\n{'='*60}")
    print(f"{name} (exit={r.returncode}):")
    print(f"STDOUT:\n{r.stdout}" if r.stdout.strip() else "STDOUT: (empty)")
    if r.stderr: print(f"STDERR: {r.stderr[:200]}")
    return r.returncode

# These are the EXACT commands that will be stored in the abilities table.
# No "powershell.exe -Command" wrapper — the agent adds that.

EDR_CMD = "$p = Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match 'MsMpEng|cb|CylanceSvc|CSFalcon|SentinelAgent|elastic-agent|winlogbeat|ossec|Tanium|CrowdStrike|bdservicehost'}; if($p){$p | Select-Object ProcessName,Id | Format-Table -AutoSize}"

PRIV_CMD = "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($i); $a=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); $g=(whoami /groups 2>&1 | Select-String 'Mandatory Label' | Out-String).Trim(); if(-not $g){$g='Medium Mandatory Level'}; Write-Output ('User: '+$i.Name); Write-Output ('IsAdmin: '+[string]$a); Write-Output ('IntegrityLevel: '+$g)"

DOM_CMD = "$cs=Get-CimInstance Win32_ComputerSystem; Write-Output ('Hostname: '+$cs.Name); Write-Output ('Domain: '+$cs.Domain); Write-Output ('PartOfDomain: '+[string]$cs.PartOfDomain); Write-Output ('DomainRole: '+[string]$cs.DomainRole)"

test("T1057.EDR — EDR Process Discovery", EDR_CMD)
test("T1033.PRIV — Privilege Context Detection", PRIV_CMD)
test("T1016.DOM — Domain Membership Detection", DOM_CMD)

print("\n" + "="*60)
print("All tests complete.")
