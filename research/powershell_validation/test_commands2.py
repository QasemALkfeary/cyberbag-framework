"""Test improved IntegrityLevel detection and EDR empty case."""
import subprocess

def test(name, cmd):
    r = subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True, text=True, timeout=15)
    print(f"\n{name} (exit={r.returncode}):")
    print(r.stdout if r.stdout else "(empty)")
    if r.stderr: print(f"STDERR: {r.stderr[:200]}")

# Improved IntegrityLevel: parse whoami /groups more robustly
test("T1033.PRIV improved",
    "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); "
    "$p=New-Object Security.Principal.WindowsPrincipal($i); "
    "$a=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
    "$wg=whoami /groups 2>&1; "
    "$ml=($wg | Select-String 'Mandatory Label' | Out-String).Trim(); "
    "if(-not $ml){$ml='Unknown'}; "
    "Write-Output ('User: '+$i.Name); "
    "Write-Output ('IsAdmin: '+[string]$a); "
    "Write-Output ('IntegrityLevel: '+$ml)"
)

# Test T1057.EDR with no match (use a fake pattern)
test("T1057.EDR (no match)",
    "$p = Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match 'FakeEDRThatDoesNotExist12345'}; "
    "if($p){$p | Select-Object ProcessName,Id | Format-Table -AutoSize}else{Write-Output ''}"
)

# Test AV condition: the condition checks stdout "not_contains" "No instances available"
test("T1518.001 check",
    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState | Format-List"
)
