param(
  [Parameter(Mandatory = $true)]
  [string]$TestBinary
)

$ErrorActionPreference = "Stop"

function Skip-HeyakiFirewallHarness {
  param([string]$Reason)
  if ($env:HEYAKI_REQUIRE_WINDOWS_FIREWALL_HARNESS -eq "1") {
    throw $Reason
  }
  Write-Host "SKIP: $Reason"
  exit 77
}

if ($env:HEYAKI_REQUIRE_WINDOWS_FIREWALL_HARNESS -ne "1") {
  Skip-HeyakiFirewallHarness "Windows firewall harness was not requested"
}
if (-not (Test-Path -LiteralPath $TestBinary -PathType Leaf)) {
  Skip-HeyakiFirewallHarness "M3A test binary is unavailable"
}
foreach ($command in @("Get-NetConnectionProfile", "Set-NetConnectionProfile",
                        "New-NetFirewallRule", "Remove-NetFirewallRule")) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    Skip-HeyakiFirewallHarness "$command is unavailable"
  }
}

$principal = [Security.Principal.WindowsPrincipal]::new(
  [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Skip-HeyakiFirewallHarness "administrator privileges are required"
}

$resolvedBinary = (Resolve-Path -LiteralPath $TestBinary).Path
$profiles = @(Get-NetConnectionProfile | Where-Object {
  $_.NetworkCategory -ne "DomainAuthenticated" -and
  ($_.IPv4Connectivity -ne "Disconnected" -or
   $_.IPv6Connectivity -ne "Disconnected")
})
if ($profiles.Count -eq 0) {
  Skip-HeyakiFirewallHarness "no mutable active network profile is available"
}

$originalProfiles = @($profiles | ForEach-Object {
  [PSCustomObject]@{
    InterfaceIndex = $_.InterfaceIndex
    NetworkCategory = $_.NetworkCategory
  }
})
$rulePrefix = "Heyaki-M3A-$PID"
$savedBlockedExpectation = $env:HEYAKI_EXPECT_MULTICAST_BLOCKED

try {
  foreach ($profile in $profiles) {
    if ($profile.NetworkCategory -ne "Public") {
      Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex `
        -NetworkCategory Public
    }
  }
  $publicProfiles = @(Get-NetConnectionProfile | Where-Object {
    $_.InterfaceIndex -in $originalProfiles.InterfaceIndex -and
    $_.NetworkCategory -eq "Public"
  })
  if ($publicProfiles.Count -eq 0) {
    throw "failed to establish an active Public network profile"
  }

  New-NetFirewallRule -DisplayName "$rulePrefix-inbound" `
    -Direction Inbound -Action Block -Enabled True -Profile Public `
    -Program $resolvedBinary -Protocol UDP -LocalPort 49189 | Out-Null
  New-NetFirewallRule -DisplayName "$rulePrefix-outbound" `
    -Direction Outbound -Action Block -Enabled True -Profile Public `
    -Program $resolvedBinary -Protocol UDP -RemotePort 49189 | Out-Null

  $env:HEYAKI_EXPECT_MULTICAST_BLOCKED = "1"
  & $resolvedBinary `
    "--gtest_filter=M3aNodeTest.BlockedMulticastFailsPeerLookupAndShutdowns"
  if ($LASTEXITCODE -ne 0) {
    throw "M3A firewall rejection test failed with exit code $LASTEXITCODE"
  }
} finally {
  if ($null -eq $savedBlockedExpectation) {
    Remove-Item Env:HEYAKI_EXPECT_MULTICAST_BLOCKED -ErrorAction SilentlyContinue
  } else {
    $env:HEYAKI_EXPECT_MULTICAST_BLOCKED = $savedBlockedExpectation
  }
  Remove-NetFirewallRule -DisplayName "$rulePrefix-inbound" `
    -ErrorAction SilentlyContinue | Out-Null
  Remove-NetFirewallRule -DisplayName "$rulePrefix-outbound" `
    -ErrorAction SilentlyContinue | Out-Null
  foreach ($profile in $originalProfiles) {
    try {
      Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex `
        -NetworkCategory $profile.NetworkCategory
    } catch {
      Write-Warning "failed to restore network profile $($profile.InterfaceIndex): $_"
    }
  }
}

Write-Host "M3A Windows Public-profile firewall rejection scenario passed"
