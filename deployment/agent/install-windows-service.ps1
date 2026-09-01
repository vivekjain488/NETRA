<#
.SYNOPSIS
    Installs the NETRA agent as a Windows service.

.DESCRIPTION
    UNTESTED. This script has not been run on Windows hardware.

    Installing a service requires administrator rights, as installing any
    service does. The running service does not: nothing the agent collects
    needs elevation. BitLocker status is the one signal that would benefit from
    it, and when unavailable that signal is reported as unknown rather than
    guessed.

.PARAMETER BinaryPath
    Full path to netra-agent.exe.

.PARAMETER BackendUrl
    The NETRA control plane this endpoint reports to.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$BackendUrl,
    [string]$ServiceName = "NetraAgent"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Installing a service requires an elevated PowerShell session."
}

if (-not (Test-Path $BinaryPath)) {
    throw "The agent binary was not found at $BinaryPath"
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping the existing $ServiceName service"
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# --service tells the agent to attach to the Service Control Manager rather
# than run in the foreground. The mode is explicit because guessing it wrong
# produces a service that never reports ready.
New-Service -Name $ServiceName `
    -BinaryPathName "`"$BinaryPath`" --service" `
    -DisplayName "NETRA endpoint agent" `
    -Description "Reports endpoint security posture and activity to the NETRA control plane." `
    -StartupType Automatic | Out-Null

# The backend URL is machine-wide configuration, not a per-session variable.
[Environment]::SetEnvironmentVariable("NETRA_BACKEND_URL", $BackendUrl, "Machine")

Write-Host "Installed $ServiceName."
Write-Host ""
Write-Host "Before starting it, obtain an enrollment token from an administrator:"
Write-Host "  POST /api/v1/enrollment-tokens"
Write-Host "then set it for the first run:"
Write-Host "  [Environment]::SetEnvironmentVariable('NETRA_ENROLLMENT_TOKEN', '<token>', 'Machine')"
Write-Host "  Start-Service $ServiceName"
Write-Host ""
Write-Host "The token is single-use. Clear it once the device has enrolled."
