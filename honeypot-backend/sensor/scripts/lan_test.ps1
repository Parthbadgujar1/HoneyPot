<#
.SYNOPSIS
  Runs the reconnaissance test activities against the honeypot sensor.

.DESCRIPTION
  Run this from a DIFFERENT device on the same network as the sensor, not
  from the sensor itself (the sensor never blocks its own machine, so the
  blocking tests would do nothing there). Only run it against a sensor you
  own or are authorised to test.

  Steps, in order. The last two can trigger automatic blocks:
    1. Reachability check
    2. Port scan of the decoy ports
    3. Banner grab and protocol fingerprint on Redis
    4. HTTP endpoint probing (sensitive paths)
    5. SSH brute force                      (needs -HoneypotPath)
    6. Honeytoken reuse                     (HIGH, auto-block)

.EXAMPLE
  .\lan_test.ps1 -Target 192.168.106.126 -HoneypotPath C:\honeypot-backend
  .\lan_test.ps1 -Target 192.168.106.126 -SkipBlockingTests
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [int]$HttpPort = 8080,
    [int]$SshPort = 2222,
    [int[]]$ScanPorts = @(21, 23, 25, 110, 1433, 2222, 6379, 8080, 9200, 27017),
    [string]$HoneypotPath,
    # Python with paramiko installed, e.g. the project venv:
    # C:\Users\Student1\Desktop\HoneyPot\venv313\Scripts\python.exe
    [string]$PythonExe = "python",
    [int]$SshAttempts = 12,
    [switch]$SkipBlockingTests
)

$ErrorActionPreference = 'Continue'

function Write-Step($number, $title) {
    Write-Host ""
    Write-Host "== $number. $title" -ForegroundColor Cyan
}

function Get-HttpStatus($url) {
    try {
        return (Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 5).StatusCode
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return "error: $($_.Exception.Message)"
    } catch {
        return "error: $($_.Exception.Message)"
    }
}

# 1. Reachability
Write-Step 1 "Reachability of $Target`:$HttpPort"
$reach = Test-NetConnection -ComputerName $Target -Port $HttpPort -WarningAction SilentlyContinue
Write-Host "TcpTestSucceeded: $($reach.TcpTestSucceeded)"
if (-not $reach.TcpTestSucceeded) {
    Write-Host "Cannot reach the decoy. Check the sensor is running and the firewall rules exist." -ForegroundColor Red
    exit 1
}

# 2. Port scan
Write-Step 2 "Port scan (expect PORT_SCAN)"
foreach ($port in $ScanPorts) {
    $open = (Test-NetConnection -ComputerName $Target -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet)
    Write-Host ("  port {0,-6} open={1}" -f $port, $open)
}

# 3. Banner grab and fingerprint on Redis
Write-Step 3 "Banner grab with HTTP fingerprint on Redis (expect BANNER_ENUMERATION)"
try {
    $client = New-Object System.Net.Sockets.TcpClient($Target, 6379)
    $stream = $client.GetStream()
    $probe = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: test`r`n`r`n")
    $stream.Write($probe, 0, $probe.Length)
    Start-Sleep -Seconds 1
    $buffer = New-Object byte[] 200
    $read = $stream.Read($buffer, 0, 200)
    Write-Host "  reply: $([Text.Encoding]::ASCII.GetString($buffer, 0, $read).Trim())"
    $client.Close()
} catch {
    Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. HTTP endpoint probing
Write-Step 4 "HTTP endpoint probing (expect HTTP_ENDPOINT_PROBING)"
$paths = @("/", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/api/v1/users")
foreach ($path in $paths) {
    $status = Get-HttpStatus "http://${Target}:${HttpPort}$path"
    Write-Host ("  {0,-16} {1}" -f $path, $status)
}

if ($SkipBlockingTests) {
    Write-Host ""
    Write-Host "Skipping blocking tests (5 and 6)." -ForegroundColor Yellow
    exit 0
}

# 5. SSH brute force (uses the honeypot's own simulator, which needs paramiko)
Write-Step 5 "SSH brute force (expect SSH_BRUTE_FORCE, may auto-block)"
if (-not $HoneypotPath) {
    Write-Host "  skipped: pass -HoneypotPath to the honeypot-backend folder (needs Python + paramiko)." -ForegroundColor Yellow
} else {
    Push-Location $HoneypotPath
    try {
        & $PythonExe -m sensor.tools.simulate_probes --host $Target --allow-remote --ssh --attempts $SshAttempts --timeout 5
    } finally {
        Pop-Location
    }
}

# 6. Honeytoken reuse (HIGH, auto-block)
Write-Step 6 "Honeytoken reuse (expect HONEYTOKEN_REUSE, HIGH, auto-block)"
try {
    $env_text = (Invoke-WebRequest -UseBasicParsing -Uri "http://${Target}:${HttpPort}/.env" -TimeoutSec 5).Content
    $line = ($env_text -split "`n") | Where-Object { $_ -like "AWS_ACCESS_KEY_ID=*" } | Select-Object -First 1
    if (-not $line) {
        Write-Host "  no honeytoken found in /.env" -ForegroundColor Yellow
    } else {
        $key = ($line -replace "AWS_ACCESS_KEY_ID=", "").Trim()
        Write-Host "  reusing token starting $($key.Substring(0, 8))..."
        # Re-send the token as a header. The decoy records the raw request.
        Invoke-WebRequest -UseBasicParsing -Uri "http://${Target}:${HttpPort}/api/v1/users" `
            -Headers @{ Authorization = $key } -TimeoutSec 5 | Out-Null
        Write-Host "  sent with Authorization header"
    }
} catch {
    Write-Host "  request sent (response: $($_.Exception.Message))"
}

Write-Host ""
Write-Host "Done. Check the Alerts and Blocks tabs at http://127.0.0.1:9100/ on the sensor machine." -ForegroundColor Green
