<#
.SYNOPSIS
    SentinelTrap end-to-end demonstration walkthrough.

.DESCRIPTION
    Calls the running backend API to:
      1. Login as admin
      2. Train all ML models
      3. Simulate attacker scenarios
      4. Analyse the highest-risk session
      5. Print summary + deception environment state
    Uses $env:BASE_URL (default http://127.0.0.1:8000/api).
#>
param(
    [string]$Base = "http://127.0.0.1:8000/api",
    [string]$User = "admin",
    [string]$Pass = "admin123",
    [string[]]$Scenarios = @("auth_attempts", "discovery", "resource_enumeration", "decoy_access", "multi_stage", "benign")
)

$ErrorActionPreference = "Stop"

function Post($url, $headers, $body) {
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"
}

Write-Host "== SentinelTrap Demo ==" -ForegroundColor Cyan
Write-Host "Base: $Base"

# 1. Login
$login = Invoke-RestMethod -Method Post -Uri "$Base/auth/login" -Body "username=$User&password=$Pass" -ContentType "application/x-www-form-urlencoded"
$tok = $login.access_token
$h = @{ Authorization = "Bearer $tok" }
Write-Host "[OK] Login as $($login.user.username) ($($login.user.role))"

# 2. Train models
try {
    $train = Invoke-RestMethod -Method Post -Uri "$Base/models/train" -Headers $h
    Write-Host "[OK] Trained classifier $($train.results.classifier.version) / anomaly $($train.results.anomaly.version) / sequence $($train.results.sequence.version)"
} catch {
    Write-Host "[SKIP] Train: $($_.Exception.Message)"
}

# 3. Simulate scenarios
foreach ($s in $Scenarios) {
    try {
        $sim = Post "$Base/honeypot/simulate?scenario=$s&n_sessions=2" $h ""
        Write-Host "[OK] Simulated $s -> $($sim.emitted) events / $($sim.sessions) sessions"
    } catch {
        Write-Host "[SKIP] Simulate $s : $($_.Exception.Message)"
    }
}

# 4. Pick highest-risk session and analyse it
$sessions = Invoke-RestMethod -Method Get -Uri "$Base/sessions?page=1&page_size=100" -Headers $h
$candidate = $sessions.items | Where-Object { $_.risk_score -ne $null } | Sort-Object risk_score -Descending | Select-Object -First 1
if (-not $candidate) { $candidate = $sessions.items | Select-Object -First 1 }

if ($candidate) {
    Write-Host "`n-- Analysing session $($candidate.session_ref) --"
    try {
        $an = Invoke-RestMethod -Method Post -Uri "$Base/sessions/$($candidate.id)/analyse" -Headers $h
        Write-Host "  classification : $($an.analysis.classification.behaviour_class)"
        Write-Host "  risk           : $($an.analysis.risk.score) / $($an.analysis.risk.severity)"
        Write-Host "  graph          : $($an.analysis.graph.stats.node_count) nodes / $($an.analysis.graph.stats.edge_count) edges"
        Write-Host "  timeline       : $($an.analysis.timeline.Count) entries"
        Write-Host "  prediction     : $($an.analysis.prediction.top1) (next stage)"
        Write-Host "  deception      : decision=$($an.analysis.deception.decision) policy=$($an.analysis.deception.policy_id)"
    } catch {
        Write-Host "[SKIP] Analyse: $($_.Exception.Message)"
    }
} else {
    Write-Host "[WARN] No sessions found to analyse."
}

# 5. Deception environment
try {
    $env2 = Invoke-RestMethod -Method Get -Uri "$Base/deception/environment" -Headers $h
    Write-Host "`nDecoy environment: $($env2.active_count) active"
    foreach ($d in $env2.decoys) {
        Write-Host ("  {0,-22} {1}" -f $d.decoy, ($(if ($d.active) { "ACTIVE" } else { "inactive" })))
    }
} catch {
    Write-Host "[SKIP] Env: $($_.Exception.Message)"
}

# 6. Dashboard summary
$ds = Invoke-RestMethod -Method Get -Uri "$Base/dashboard/summary" -Headers $h
Write-Host "`nDashboard summary: sessions=$($ds.total_sessions) high-risk=$($ds.high_risk_sessions) anomalies=$($ds.anomalies) events=$($ds.total_events) predictions=$($ds.predictions) adaptive=$($ds.adaptive_actions)"

Write-Host "`nDemo complete." -ForegroundColor Green
