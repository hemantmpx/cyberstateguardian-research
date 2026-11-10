param(
  [Parameter(Mandatory=$true)][string]$ApiUrl,
  [string]$HostId = "win11-arm-lab",
  [Parameter(Mandatory=$true)][string]$Token,
  [ValidateRange(5,3600)][int]$IntervalSeconds = 30,
  [string]$PythonExe = "python.exe",
  [string]$InstallRoot = "$env:ProgramFiles\CyberStateGuardian\Probe",
  [string]$TaskName = "CyberStateGuardian Probe",
  [switch]$NoScheduledTask,
  [switch]$EnableTransitionCapture,
  [switch]$CaptureProcesses,
  [switch]$CaptureServices,
  [switch]$CaptureRegistry,
  [switch]$CaptureTasks,
  [switch]$CapturePrivilegedGroups,
  [switch]$CaptureListeners,
  [ValidateRange(1,3600)][int]$TransitionPollIntervalSeconds = 5
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
  throw "Run this installer from an Administrator PowerShell window."
}

if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq 'replace-with-lab-token') {
  throw "Supply the actual lab token."
}
$requestedTransitionCategories = @(
  $CaptureProcesses, $CaptureServices, $CaptureRegistry, $CaptureTasks,
  $CapturePrivilegedGroups, $CaptureListeners
) -contains $true
if ($requestedTransitionCategories -and -not $EnableTransitionCapture) {
  throw "Category capture switches require -EnableTransitionCapture."
}
if ($EnableTransitionCapture -and -not $requestedTransitionCategories) {
  throw "EnableTransitionCapture requires at least one -Capture* category switch."
}
$uri = [Uri]$ApiUrl
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http','https')) { throw "Invalid API URL." }
$python = (Get-Command $PythonExe -ErrorAction Stop).Source
if ($python.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Use machine-wide Python, not an interpreter installed in the current user's profile."
}
& $python -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Machine-wide Python 3.12+ is required." }
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$transitionDataRoot = Join-Path $env:ProgramData 'CyberStateGuardian'
New-Item -ItemType Directory -Path $transitionDataRoot -Force | Out-Null
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
  $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
  )
  $acl.AddAccessRule($rule)
}
Set-Acl -Path $InstallRoot -AclObject $acl
Set-Acl -Path $transitionDataRoot -AclObject $acl
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName
}
$venv = Join-Path $InstallRoot 'venv'
& $python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
$python = Join-Path $venv 'Scripts\python.exe'
& $python -m pip install --upgrade $PSScriptRoot
if ($LASTEXITCODE -ne 0) { throw "Standalone probe installation failed; task not registered." }
$configPath = Join-Path $InstallRoot 'settings.json'
@{
  CSG_PROBE_API_URL = $ApiUrl
  CSG_PROBE_HOST_ID = $HostId
  CSG_PROBE_TOKEN = $Token
  CSG_PROBE_INTERVAL_SECONDS = $IntervalSeconds
  CSG_TRANSITION_CAPTURE_ENABLED = [bool]$EnableTransitionCapture
  CSG_TRANSITION_PROCESSES_ENABLED = [bool]$CaptureProcesses
  CSG_TRANSITION_SERVICES_ENABLED = [bool]$CaptureServices
  CSG_TRANSITION_REGISTRY_ENABLED = [bool]$CaptureRegistry
  CSG_TRANSITION_TASKS_ENABLED = [bool]$CaptureTasks
  CSG_TRANSITION_PRIVILEGED_GROUPS_ENABLED = [bool]$CapturePrivilegedGroups
  CSG_TRANSITION_LISTENERS_ENABLED = [bool]$CaptureListeners
  CSG_TRANSITION_POLL_INTERVAL_SECONDS = $TransitionPollIntervalSeconds
  CSG_TRANSITION_SPOOL_PATH = (Join-Path $transitionDataRoot 'transition-spool.jsonl')
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

if (-not $NoScheduledTask) {
  $action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "-m cyberstateguardian_probe.main --config `"$configPath`" --log-level INFO" `
    -WorkingDirectory $InstallRoot
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "Task '$TaskName' registered; start requested. Verify a new SYSTEM observation in CSG."
} else {
  & $python -m cyberstateguardian_probe.main --config $configPath --once
  if ($LASTEXITCODE -ne 0) { throw "One-shot upload failed." }
}

Write-Host "Probe interpreter: $python"
Write-Host "Restricted configuration: $configPath (contains a secret)"
Write-Host "Verify with: Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
