$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root

$pidPath = Join-Path $Root 'data\server.pid'
if (-not (Test-Path $pidPath)) {
    Write-Host 'EUVD Dependency Workbench is not running.'
    exit 0
}

$serverPid = 0
if (-not [int]::TryParse((Get-Content -Raw -LiteralPath $pidPath).Trim(), [ref]$serverPid)) {
    throw "Invalid server PID file: $pidPath"
}

$process = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
if ($process) {
    $runtimePython = (Join-Path $Root 'runtime\python.exe')
    $runtimePythonw = (Join-Path $Root 'runtime\pythonw.exe')
    $processPath = $null
    try { $processPath = $process.Path } catch { }
    if ($processPath -and $processPath -notin @($runtimePython, $runtimePythonw)) {
        throw "PID $serverPid does not belong to this tool. Refusing to stop it."
    }
    Stop-Process -Id $serverPid -Force
}

Remove-Item -LiteralPath $pidPath -Force
Write-Host 'EUVD Dependency Workbench stopped. Local data and reports were kept.'
