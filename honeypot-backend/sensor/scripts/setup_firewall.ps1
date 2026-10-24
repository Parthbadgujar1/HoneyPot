<#
.SYNOPSIS
  Prepares Windows Defender Firewall for the honeypot sensor, or undoes it.

.DESCRIPTION
  Default (apply) mode:
    1. Turns on logging of DROPPED inbound connections (and ICMP drops) so the
       sensor can see port scans and ping sweeps aimed at closed ports.
       Logging of allowed connections is turned off to keep the log small.
    2. Creates inbound ALLOW rules only for the decoy ports listed in
       sensor/config.json (SSH, HTTP and bait ports). Nothing else is opened.
       The operator console is never opened: it listens on 127.0.0.1 only.

  -Undo mode:
    Removes every HP-DECOY-* allow rule and every HP-BLOCK-* block rule that the
    sensor created, and turns dropped-connection logging back off.

  Run from an elevated (Administrator) PowerShell. Use -WhatIf to preview.

.EXAMPLE
  .\setup_firewall.ps1 -WhatIf
  .\setup_firewall.ps1
  .\setup_firewall.ps1 -Undo
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Undo,
    [string]$ConfigPath,
    [ValidateSet('Domain', 'Private', 'Public', 'Any')]
    [string[]]$NetworkProfile = @('Domain', 'Private', 'Public'),
    [int]$LogMaxSizeKB = 16384
)

$ErrorActionPreference = 'Stop'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    throw 'Run this script from an elevated (Administrator) PowerShell window.'
}

# Resolved here, not in the param block: $PSScriptRoot is empty while
# parameter defaults are bound, which made Join-Path fail.
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PSScriptRoot '..\config.json'
}
$config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$logPath = $config.firewall_log.path
if (-not $logPath) { $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" }

# Decoy ports come from the same config the sensor uses, so the two cannot disagree.
$decoyPorts = @()
if ($config.decoys.ssh.enabled) {
    $decoyPorts += [pscustomobject]@{ Name = 'SSH'; Port = [int]$config.decoys.ssh.port }
}
if ($config.decoys.http.enabled) {
    $decoyPorts += [pscustomobject]@{ Name = 'HTTP'; Port = [int]$config.decoys.http.port }
}
if ($config.decoys.bait.enabled) {
    foreach ($property in $config.decoys.bait.services.PSObject.Properties) {
        $decoyPorts += [pscustomobject]@{ Name = $property.Value.ToUpper(); Port = [int]$property.Name }
    }
}

if ($Undo) {
    $rules = Get-NetFirewallRule -DisplayName 'HP-DECOY-*', 'HP-BLOCK-*' -ErrorAction SilentlyContinue
    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove firewall rule')) {
            Remove-NetFirewallRule -Name $rule.Name
            Write-Host "Removed $($rule.DisplayName)"
        }
    }
    if ($PSCmdlet.ShouldProcess('all profiles', 'Turn off dropped-connection logging')) {
        netsh advfirewall set allprofiles logging droppedconnections disable | Out-Null
        Write-Host 'Dropped-connection logging turned off.'
    }
    return
}

Write-Host 'Decoy ports to open (inbound, TCP):'
$decoyPorts | ForEach-Object { Write-Host ("  {0,-16} {1}" -f $_.Name, $_.Port) }
Write-Host ("Profiles: {0}" -f ($NetworkProfile -join ', '))
if ($NetworkProfile -contains 'Public') {
    Write-Warning 'Opening decoy ports on the Public profile exposes them to every host on the network. Only do this on a network where IT has approved the honeypot.'
}

foreach ($decoy in $decoyPorts) {
    $name = "HP-DECOY-$($decoy.Name)-$($decoy.Port)"
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Already present: $name"
        continue
    }
    if ($PSCmdlet.ShouldProcess($name, "Allow inbound TCP $($decoy.Port)")) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $decoy.Port -Profile $NetworkProfile `
            -Description 'Honeypot decoy listener (sensor/config.json)' | Out-Null
        Write-Host "Created $name"
    }
}

if ($PSCmdlet.ShouldProcess('all profiles', 'Turn on dropped-connection logging')) {
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    netsh advfirewall set allprofiles logging allowedconnections disable | Out-Null
    netsh advfirewall set allprofiles logging maxfilesize $LogMaxSizeKB | Out-Null
    netsh advfirewall set allprofiles logging filename "$logPath" | Out-Null
    Write-Host "Dropped-connection logging on: $logPath (max $LogMaxSizeKB KB)"
    Write-Host 'Set "firewall_log.enabled" to true in sensor/config.json so the sensor reads this log.'
}
