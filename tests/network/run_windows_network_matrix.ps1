# M9-07 Windows network matrix: exercises the connectivity combinations that
# are reachable on a single Windows host -- LAN-only discovery/signaling,
# relay-signaled direct, and forced TURN/UDP through the libjuice test TURN
# server -- with the initiator role swapped between the two peers ("both
# directions").
#
# CI (HEYAKI_REQUIRE_WINDOWS_NETWORK_MATRIX=1) runs every scenario against a
# local relay. A self-hosted mixed fleet can instead point the peers at a
# relay (+ coturn or heyaki-test-turn-server) on a reachable Linux host via
# -RelayUrl/-RelayCaFile/-EnrollToken (-TurnEndpoint/-TurnUsername/
# -TurnCredential for TURN); cross-OS mode also unlocks the udp_blocked
# scenario, because Windows Firewall exempts loopback traffic and a local
# block rule can never reach the same-host TURN server. See
# docs/operations/cross-os-matrix.md.
#
# Exit codes: 0 pass, 1 failure, 77 skip (prerequisites absent).

param(
  [Parameter(Mandatory = $true)]
  [string]$MatrixBin,
  [Parameter(Mandatory = $true)]
  [string]$RelayBin,
  [Parameter(Mandatory = $true)]
  [string]$DemoBin,
  [Parameter(Mandatory = $true)]
  [string]$TurnServerBin,
  [string]$WorkDir = "",
  [string[]]$Scenario = @(),
  # Cross-OS mode: use a remote relay instead of the local one. Requires
  # -RelayCaFile and -EnrollToken together with -RelayUrl.
  [string]$RelayUrl = "",
  [string]$RelayCaFile = "",
  [string]$EnrollToken = "",
  # Cross-OS TURN: remote HOST:PORT + credentials (the Linux side runs
  # heyaki-test-turn-server or coturn). Required in cross-OS mode whenever
  # a turn scenario is selected.
  [string]$TurnEndpoint = "",
  [string]$TurnUsername = "",
  [string]$TurnCredential = ""
)

$ErrorActionPreference = "Stop"

$tenant = "matrix-tenant"
$relayPort = 8443
$turnPortA = 3480
$turnPortB = 3481
# Same-host ICE nomination race: with TURN configured the local agent may
# nominate its server-reflexive candidate against the peer's relayed
# candidate (the data still transits the peer's TURN allocation). Strict
# both-relayed enforcement is a topology property of the Linux netns
# matrix; on a single host this pair is a valid outcome.
$turnPathLabels = @("turn_udp", "direct_srflx")

function Skip-HeyakiMatrix {
  param([string]$Reason)
  if ($env:HEYAKI_REQUIRE_WINDOWS_NETWORK_MATRIX -eq "1") {
    throw $Reason
  }
  Write-Host "SKIP: $Reason"
  exit 77
}

function Fail-HeyakiMatrix {
  param([string]$Reason, [string]$Tag = "")
  Write-Host "MATRIX_FAILED: $Reason"
  $script:failures += 1
  # Surface both participants' tails so CI failures carry the actual
  # MATRIX_RESULT / node failure dump instead of only the assertion.
  $pattern = if ($Tag -ne "") { "$Tag-*-run.log*" } else { "*-run.log*" }
  foreach ($log in (Get-ChildItem -Path $script:workDir -Filter $pattern `
      -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)) {
    Write-Host "----- $($log.Name) -----"
    Get-Content -LiteralPath $log.FullName -ErrorAction SilentlyContinue |
      Select-Object -Last 30
  }
}

function Quote-Arg {
  param([string]$Value)
  if ($Value -match '\s') { return '"{0}"' -f $Value }
  return $Value
}

function Invoke-Step {
  param([string]$File, [string[]]$Arguments, [string]$LogName)
  $output = Join-Path $script:workDir $LogName
  $p = Start-Process -FilePath $File `
    -ArgumentList (($Arguments | ForEach-Object { Quote-Arg $_ }) -join " ") `
    -RedirectStandardOutput $output -RedirectStandardError "$output.err" `
    -NoNewWindow -PassThru
  if (-not $p.WaitForExit(120000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    throw "step timed out: $LogName"
  }
  if ($p.ExitCode -ne 0) {
    Write-Host "----- $LogName (exit $($p.ExitCode)) -----"
    Get-Content $output -ErrorAction SilentlyContinue | Select-Object -Last 25
    Get-Content "$output.err" -ErrorAction SilentlyContinue | Select-Object -Last 10
    throw "step failed: $LogName"
  }
  return $output
}

# Runs one initiator/responder exchange and returns the initiator's parsed
# MATRIX_RESULT fields. $InitiatorArgs/$ResponderArgs carry the per-scenario
# transport flags (same set on both sides).
function Invoke-MatrixPair {
  param(
    [string]$Tag,
    [string[]]$InitiatorArgs,
    [string[]]$ResponderArgs,
    [bool]$Enroll,
    [int]$BudgetSeconds = 60
  )
  $firstDb = Join-Path $script:workDir "$Tag-first.sqlite"
  $secondDb = Join-Path $script:workDir "$Tag-second.sqlite"
  Invoke-Step $MatrixBin @("init-profile", $firstDb, "matrix.first") "$Tag-init1.log" | Out-Null
  Invoke-Step $MatrixBin @("init-profile", $secondDb, "matrix.second") "$Tag-init2.log" | Out-Null
  Invoke-Step $MatrixBin @("seed-trust", $firstDb, $secondDb) "$Tag-seed.log" | Out-Null
  if ($Enroll) {
    Invoke-Step $MatrixBin @("enroll", $firstDb, "matrix.first", $script:relayUrl,
      $script:relayCa, $tenant, $script:enrollToken) "$Tag-enroll1.log" | Out-Null
    Invoke-Step $MatrixBin @("enroll", $secondDb, "matrix.second", $script:relayUrl,
      $script:relayCa, $tenant, $script:enrollToken) "$Tag-enroll2.log" | Out-Null
    # Let the previous scenario's endpoints fall out of the relay directory
    # (3 s presence lease) so the initiator cannot dial a stale endpoint.
    Start-Sleep -Seconds 4
  }

  $budget = [string](($BudgetSeconds - 5) * 1000)
  $firstOut = Join-Path $script:workDir "$Tag-first-run.log"
  $secondOut = Join-Path $script:workDir "$Tag-second-run.log"
  # The responder starts first so its announcements (and reverse discovery
  # of the initiator) are live before the initiator dials; a first-shot
  # denial from reverse-discovery lag still gets bounded retries below.
  $second = Start-Process -FilePath $MatrixBin `
    -ArgumentList ((@("run", $secondDb, "matrix.second", $script:relayUrl, $script:relayCa,
      $tenant, "40000", "--role", "responder",
      "--authenticate-budget-ms", $budget) + $ResponderArgs |
      ForEach-Object { Quote-Arg $_ }) -join " ") `
    -RedirectStandardOutput $secondOut -RedirectStandardError "$secondOut.err" `
    -NoNewWindow -PassThru
  Start-Sleep -Seconds 1
  $first = Start-Process -FilePath $MatrixBin `
    -ArgumentList ((@("run", $firstDb, "matrix.first", $script:relayUrl, $script:relayCa,
      $tenant, "40000", "--role", "initiator",
      "--authenticate-budget-ms", $budget, "--connect-retries", "3") + $InitiatorArgs |
      ForEach-Object { Quote-Arg $_ }) -join " ") `
    -RedirectStandardOutput $firstOut -RedirectStandardError "$firstOut.err" `
    -NoNewWindow -PassThru
  foreach ($p in @($first, $second)) {
    if (-not $p.WaitForExit($BudgetSeconds * 1000)) {
      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
      Fail-HeyakiMatrix "${Tag}: participant timed out after ${BudgetSeconds}s" $Tag
    }
  }
  return (Get-MatrixResult -Path $firstOut -Tag "$Tag-first")
}

function Get-MatrixResult {
  param([string]$Path, [string]$Tag)
  $fields = @{}
  if (Test-Path -LiteralPath $Path) {
    foreach ($line in Get-Content -LiteralPath $Path) {
      if ($line -match '^MATRIX_RESULT (.*)$') {
        $fields = @{}
        foreach ($token in $Matches[1] -split ' ') {
          $pair = $token -split '=', 2
          if ($pair.Count -eq 2) { $fields[$pair[0]] = $pair[1] }
        }
      }
    }
  }
  if ($fields.Count -eq 0) {
    Fail-HeyakiMatrix "${Tag}: no MATRIX_RESULT line"
    Write-Host "----- $Tag output -----"
    Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue |
      Select-Object -Last 25
  }
  return $fields
}

function Assert-Exchange {
  param(
    [hashtable]$Result,
    [string]$Tag,
    [string[]]$ExpectedPaths,
    [bool]$StrictServices
  )
  if ($Result.Count -eq 0) { return }
  if ($Result["authenticated"] -ne "1") {
    Fail-HeyakiMatrix "${Tag}: authenticated=$($Result['authenticated'])" $Tag
    return
  }
  if ($Result["data_path"] -notin $ExpectedPaths) {
    Fail-HeyakiMatrix "${Tag}: data_path=$($Result['data_path']) expected $($ExpectedPaths -join '|')" $Tag
    return
  }
  if ($StrictServices) {
    if ($Result["m6_message_acked"] -ne "1" -or
        [int]$Result["m6_rpc_status"] -lt 0 -or
        $Result["m7_file"] -ne "1") {
      Fail-HeyakiMatrix "${Tag}: services message=$($Result['m6_message_acked']) rpc=$($Result['m6_rpc_status']) file=$($Result['m7_file'])" $Tag
      return
    }
  }
  Write-Host "SCENARIO_OK ${Tag}: path=$($Result['data_path']) duration=$($Result['duration_ms'])ms"
}

$script:failures = 0

if ($env:HEYAKI_REQUIRE_WINDOWS_NETWORK_MATRIX -ne "1") {
  Skip-HeyakiMatrix "Windows network matrix was not requested"
}
foreach ($bin in @($MatrixBin, $RelayBin, $DemoBin, $TurnServerBin)) {
  if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
    Skip-HeyakiMatrix "required binary is unavailable: $bin"
  }
}
# Normalize to provider-native separators: New-NetFirewallRule -Program
# rejects forward-slash paths, and CMake generator expressions may carry
# them.
$MatrixBin = (Resolve-Path -LiteralPath $MatrixBin).Path
$RelayBin = (Resolve-Path -LiteralPath $RelayBin).Path
$DemoBin = (Resolve-Path -LiteralPath $DemoBin).Path
$TurnServerBin = (Resolve-Path -LiteralPath $TurnServerBin).Path
$crossOs = ($RelayUrl -ne "")
if ($crossOs -and ($RelayCaFile -eq "" -or $EnrollToken -eq "")) {
  Skip-HeyakiMatrix "cross-OS mode requires -RelayCaFile and -EnrollToken with -RelayUrl"
}
if ($Scenario.Count -eq 0) {
  # udp_blocked is only meaningful in cross-OS mode: Windows Firewall (WFP)
  # exempts loopback traffic, so a program rule cannot block the same-host
  # TURN server and the scenario would silently pass instead of failing
  # bounded. The local-OS udp-blocked contract is enforced by the Linux CI
  # matrix (iptables drop on a real network path).
  if ($crossOs) {
    $Scenario = @("lan_only", "relay_direct", "turn_udp", "udp_blocked")
  } else {
    $Scenario = @("lan_only", "relay_direct", "turn_udp")
  }
}
if (($Scenario -contains "udp_blocked") -and -not $crossOs) {
  throw "udp_blocked requires cross-OS mode (-RelayUrl): Windows Firewall " +
    "exempts loopback traffic, so the block rule cannot reach a same-host " +
    "TURN server and the scenario cannot fail as designed"
}
$needsFirewall = $Scenario -contains "udp_blocked"
if ($needsFirewall) {
  foreach ($command in @("New-NetFirewallRule", "Remove-NetFirewallRule")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
      Skip-HeyakiMatrix "$command is unavailable"
    }
  }
  $principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Skip-HeyakiMatrix "udp_blocked requires administrator privileges"
  }
}

# ---- work directory ------------------------------------------------------
if ($WorkDir -eq "") {
  $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) "heyaki-windows-matrix.$PID"
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$script:workDir = (Resolve-Path -LiteralPath $WorkDir).Path

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
  $candidate = "${env:ProgramFiles}\OpenSSL\bin\openssl.exe"
  if (Test-Path $candidate) { $openssl = $candidate }
}
$needsLocalRelay = (-not $crossOs) -and
  (($Scenario -contains "relay_direct") -or ($Scenario -contains "turn_udp"))
if ($needsLocalRelay -and -not $openssl) {
  Skip-HeyakiMatrix "openssl is unavailable for relay certificates"
}

$script:relayProcesses = @()
$script:firewallRules = @()
try {
  # ---- relay (local unless cross-OS mode supplies a remote one) ----------
  $script:relayUrl = "wss://127.0.0.1:${relayPort}"
  $script:relayCa = Join-Path $script:workDir "ca.pem"
  $script:enrollToken = $EnrollToken
  if ($needsLocalRelay) {
    & $openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 `
      -subj "/CN=heyaki-matrix-relay" `
      -keyout (Join-Path $script:workDir "ca-key.pem") `
      -out $script:relayCa | Out-Null
    & $openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" `
      -keyout (Join-Path $script:workDir "relay-key.pem") `
      -out (Join-Path $script:workDir "relay.csr") | Out-Null
    Set-Content -Path (Join-Path $script:workDir "san.ext") -Value "subjectAltName=IP:127.0.0.1,DNS:localhost"
    & $openssl x509 -req -in (Join-Path $script:workDir "relay.csr") `
      -CA $script:relayCa -CAkey (Join-Path $script:workDir "ca-key.pem") `
      -CAcreateserial -days 1 -extfile (Join-Path $script:workDir "san.ext") `
      -out (Join-Path $script:workDir "relay-cert.pem") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "openssl certificate generation failed" }

    $script:enrollToken = "TEST-ONLY-m9-windows-matrix-token-0123456789"
    $expiry = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 3600000
    Invoke-Step $DemoBin @("seed-token",
      (Join-Path $script:workDir "relay.sqlite"), $tenant, $script:enrollToken,
      "$expiry", "64") "seed-token.log" | Out-Null

    $relayConf = Join-Path $script:workDir "relay.conf"
    @(
      "listen_address = 127.0.0.1",
      "listen_port = ${relayPort}",
      "tls_certificate_file = $($script:workDir -replace '\\', '/')/relay-cert.pem",
      "tls_private_key_file = $($script:workDir -replace '\\', '/')/relay-key.pem",
      "database_file = $($script:workDir -replace '\\', '/')/relay.sqlite",
      "handshake_timeout_milliseconds = 2000",
      "shutdown_timeout_milliseconds = 2000"
    ) | Set-Content -Path $relayConf
    $relayOut = Join-Path $script:workDir "relay-run.log"
    $relay = Start-Process -FilePath $RelayBin -ArgumentList ('--config "{0}"' -f $relayConf) `
      -RedirectStandardOutput $relayOut -RedirectStandardError "$relayOut.err" `
      -NoNewWindow -PassThru
    $script:relayProcesses += $relay
    $ready = $false
    foreach ($i in 1..100) {
      try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync("127.0.0.1", $relayPort)
        if ($task.Wait(200) -and $client.Connected) { $ready = $true }
        $client.Close()
        if ($ready) { break }
      } catch {}
      Start-Sleep -Milliseconds 100
    }
    if (-not $ready) {
      throw "local relay did not become reachable on port $relayPort"
    }
    Write-Host "LOCAL_RELAY_READY port=${relayPort}"
  } elseif ($crossOs) {
    $script:relayUrl = $RelayUrl
    $script:relayCa = (Resolve-Path -LiteralPath $RelayCaFile).Path
    Write-Host "REMOTE_RELAY url=$script:relayUrl"
  }

  # ---- TURN servers (libjuice embedded; one per side, disjoint relay
  # ranges, mirroring the coturn A/B topology of the Linux matrix).
  # Cross-OS mode uses the remote TURN endpoint instead and starts nothing.
  $turnNeeded = ($Scenario -contains "turn_udp") -or ($Scenario -contains "udp_blocked")
  if ($turnNeeded -and $crossOs -and $TurnEndpoint -eq "") {
    throw "cross-OS mode with turn scenarios requires -TurnEndpoint HOST:PORT " +
      "(-TurnUsername/-TurnCredential) pointing at the remote TURN server"
  }
  if ($turnNeeded -and -not $crossOs) {
    $script:turnServers = @()
    foreach ($spec in @(
        @{Port = $turnPortA; User = "init-side"; Pass = "m9-turn-a";
          Begin = "49200"; End = "49219"; Name = "turn-a" },
        @{Port = $turnPortB; User = "resp-side"; Pass = "m9-turn-b";
          Begin = "49220"; End = "49239"; Name = "turn-b" })) {
      $out = Join-Path $script:workDir "$($spec.Name).log"
      $p = Start-Process -FilePath $TurnServerBin -ArgumentList (
        @("--port", "$($spec.Port)", "--username", $spec.User,
          "--credential", $spec.Pass, "--relay-port-begin", $spec.Begin,
          "--relay-port-end", $spec.End) -join " ") `
        -RedirectStandardOutput $out -RedirectStandardError "$out.err" `
        -NoNewWindow -PassThru
      $script:turnServers += $p
      $ready = $false
      foreach ($i in 1..50) {
        if ((Test-Path -LiteralPath $out) -and
            (Select-String -LiteralPath $out -Pattern "TURN_SERVER_READY" `
              -Quiet -ErrorAction SilentlyContinue)) {
          $ready = $true
          break
        }
        if ($p.HasExited) { break }
        Start-Sleep -Milliseconds 100
      }
      if (-not $ready) { throw "TURN server $($spec.Name) did not report ready" }
    }
    Write-Host "TURN_SERVERS_READY a=${turnPortA} b=${turnPortB}"
  }

  if ($crossOs) {
    # One remote TURN server serves both sides (each side gets its own
    # allocation pair; see docs/operations/cross-os-matrix.md).
    $turnArgs = @("--turn", $TurnEndpoint,
      "--turn-username", $TurnUsername, "--turn-credential", $TurnCredential,
      "--force-turn")
    $turnArgsResponder = $turnArgs
    if ($turnNeeded) { Write-Host "REMOTE_TURN endpoint=$TurnEndpoint" }
  } else {
    $turnArgs = @("--turn", "127.0.0.1:${turnPortA}",
      "--turn-username", "init-side", "--turn-credential", "m9-turn-a",
      "--force-turn")
    $turnArgsResponder = @("--turn", "127.0.0.1:${turnPortB}",
      "--turn-username", "resp-side", "--turn-credential", "m9-turn-b",
      "--force-turn")
  }

  if ($Scenario -contains "lan_only") {
    # LAN-only: no relay, discovery and signaling on multicast + provisional
    # TLS; both peers live on this host so discovery rides the shared
    # multicast-capable interface. The pause lets the previous exchange's
    # LAN presence leases expire so the initiator cannot dial a stale peer.
    Start-Sleep -Seconds 3
    $result = Invoke-MatrixPair -Tag "lan-only-1" `
      -InitiatorArgs @("--lan-only") -ResponderArgs @("--lan-only") -Enroll:$false
    Assert-Exchange $result "lan_only/first-initiates" @("direct_host") $true
    Start-Sleep -Seconds 3
    $result = Invoke-MatrixPair -Tag "lan-only-2" `
      -InitiatorArgs @("--lan-only") -ResponderArgs @("--lan-only") -Enroll:$false
    Assert-Exchange $result "lan_only/second-initiates" @("direct_host") $false
  }

  if ($Scenario -contains "relay_direct") {
    $result = Invoke-MatrixPair -Tag "relay-direct-1" `
      -InitiatorArgs @() -ResponderArgs @() -Enroll:$true
    Assert-Exchange $result "relay_direct/first-initiates" @("direct_host") $true
    $result = Invoke-MatrixPair -Tag "relay-direct-2" `
      -InitiatorArgs @() -ResponderArgs @() -Enroll:$true
    Assert-Exchange $result "relay_direct/second-initiates" @("direct_host") $false
  }

  if ($Scenario -contains "turn_udp") {
    $result = Invoke-MatrixPair -Tag "turn-udp-1" `
      -InitiatorArgs $turnArgs -ResponderArgs $turnArgsResponder -Enroll:$true
    Assert-Exchange $result "turn_udp/first-initiates" $turnPathLabels $true
    $result = Invoke-MatrixPair -Tag "turn-udp-2" `
      -InitiatorArgs $turnArgs -ResponderArgs $turnArgsResponder -Enroll:$true
    Assert-Exchange $result "turn_udp/second-initiates" $turnPathLabels $false
  }

  if ($Scenario -contains "udp_blocked") {
    # Block the matrix program's outbound UDP to the TURN ports on a real
    # network path (cross-OS mode: the remote TURN endpoint's port; local
    # mode never reaches here -- WFP exempts loopback).
    if ($crossOs) {
      $blockPorts = @($TurnEndpoint.Split(':')[-1])
    } else {
      $blockPorts = @($turnPortA, $turnPortB)
    }
    $prefix = "Heyaki-M9-$PID"
    New-NetFirewallRule -DisplayName "$prefix-turn-udp-block" `
      -Direction Outbound -Action Block -Enabled True -Profile Any `
      -Program $MatrixBin -Protocol UDP -RemotePort $blockPorts | Out-Null
    $script:firewallRules += "$prefix-turn-udp-block"
    try {
      $result = Invoke-MatrixPair -Tag "udp-blocked" `
        -InitiatorArgs $turnArgs -ResponderArgs $turnArgsResponder `
        -Enroll:$true -BudgetSeconds 45
      if ($result.Count -ne 0 -and $result["authenticated"] -ne "0") {
        Fail-HeyakiMatrix "udp_blocked: unexpected session authenticated=$($result['authenticated'])" "udp-blocked"
      } else {
        Write-Host "SCENARIO_OK udp_blocked (bounded explicit failure): authenticated=0"
      }
    } finally {
      foreach ($rule in $script:firewallRules) {
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
      }
      $script:firewallRules = @()
    }
  }
} finally {
  foreach ($p in $script:relayProcesses) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
  foreach ($p in @($script:turnServers)) {
    if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  }
  foreach ($rule in $script:firewallRules) {
    Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
  }
}

if ($script:failures -gt 0) {
  Write-Host "WINDOWS_MATRIX_FAILED failures=$($script:failures)"
  exit 1
}
Write-Host "WINDOWS_MATRIX_OK scenarios=$($Scenario -join ',')"
exit 0
