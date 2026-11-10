param(
    [string]$OutputPath = "C:\CSG\sysmon-runtime-config.json"
)

$ErrorActionPreference = "Stop"
$service = Get-CimInstance Win32_Service | Where-Object {
    $_.Name -in @("Sysmon64a", "Sysmon64", "Sysmon")
} | Select-Object -First 1
if (-not $service) { throw "A Sysmon service was not found." }

$exeMatch = [regex]::Match(
    [string]$service.PathName,
    '^\s*"?([^"].*?\.exe)"?(?:\s|$)',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
if (-not $exeMatch.Success) { throw "Could not resolve Sysmon executable from its service path." }
$executable = $exeMatch.Groups[1].Value.Trim('"')
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Sysmon executable is missing: $executable"
}

$oldErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $output = @(& $executable -c 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $oldErrorActionPreference
}
$runtimeText = [regex]::Replace(($output -join "`n"), '\x00', '')
$pathMatch = [regex]::Match($runtimeText, '(?im)^\s*-\s*Config file:\s*(.+?)\s*$')
$hashMatch = [regex]::Match($runtimeText, '(?im)^\s*-\s*Config hash:\s*SHA256=([0-9a-f]{64})\s*$')
if ($exitCode -ne 0 -or -not $pathMatch.Success -or -not $hashMatch.Success) {
    throw "Sysmon runtime configuration query failed (exit=$exitCode)."
}

$configPath = $pathMatch.Groups[1].Value.Trim()
$configExists = Test-Path -LiteralPath $configPath -PathType Leaf
$configHash = if ($configExists) {
    (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
} else { $null }
$networkConnect = @()
if ($configExists) {
    [xml]$config = Get-Content -LiteralPath $configPath -Raw
    $networkConnect = @($config.SelectNodes("/Sysmon/EventFiltering/NetworkConnect") | ForEach-Object {
        $attributes = [ordered]@{}
        foreach ($attribute in $_.Attributes) { $attributes[$attribute.Name] = $attribute.Value }
        [ordered]@{
            attributes = $attributes
            rules = @($_.ChildNodes | ForEach-Object { $_.OuterXml })
        }
    })
}

$result = [ordered]@{
    schema_version = 1
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    service = [ordered]@{
        name = [string]$service.Name
        state = [string]$service.State
        process_id = [int]$service.ProcessId
        image_path = [string]$service.PathName
    }
    executable_path = $executable
    runtime_query_exit_code = $exitCode
    active_config_path = $configPath
    active_config_hash_sha256 = $hashMatch.Groups[1].Value.ToLowerInvariant()
    config_file_exists = $configExists
    config_file_hash_sha256 = $configHash
    active_hash_matches_file = [bool]($configExists -and $configHash -eq $hashMatch.Groups[1].Value.ToLowerInvariant())
    network_connect_filters = $networkConnect
    runtime_output = $runtimeText
}

$json = $result | ConvertTo-Json -Depth 12
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$json
