param(
    [switch]$WithData
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ($WithData) {
    throw '-WithData is disabled: public portable exports must never contain customer data, EUVD databases, reports, backups, or runtime state.'
}

$RuntimePython = Join-Path $Root 'runtime\python.exe'
if (Test-Path -LiteralPath $RuntimePython) {
    $PythonCommand = $RuntimePython
    $PythonPrefixArgs = @()
} else {
    $PythonInfo = Get-Command python.exe, python -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $PythonInfo) {
        throw 'Python is required to stage the allowlisted portable source. Run scripts\setup-runtime.ps1 or install Python 3.'
    }
    $PythonCommand = $PythonInfo.Source
    $PythonPrefixArgs = @()
}

$exportDir = Join-Path $Root 'exports'
New-Item -ItemType Directory -Force -Path $exportDir | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$stageDir = Join-Path $Root ".export-stage-$timestamp"
$stageRoot = Join-Path $stageDir 'euvd-sbom-matcher'
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

try {
    & $PythonCommand @PythonPrefixArgs (Join-Path $PSScriptRoot 'build_portable_candidate.py') --output $stageRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Allowlisted portable staging failed.'
    }

    $zipName = "euvd-sbom-matcher-portable-$timestamp.zip"
    $zipPath = Join-Path $exportDir $zipName
    Compress-Archive -LiteralPath $stageRoot -DestinationPath $zipPath -CompressionLevel Optimal

    Write-Host "Portable package created: $zipPath"
    Write-Host 'Data-free allowlist enforced: no .git, data, backups, self-test, runtime, outputs, exports, .serena, or rights-pending binary assets.'
} finally {
    if (Test-Path -LiteralPath $stageDir) {
        $resolvedStage = (Resolve-Path -LiteralPath $stageDir).Path
        if ($resolvedStage.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
