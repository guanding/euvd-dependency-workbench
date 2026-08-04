param(
    [switch]$WithData
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$driveRoot = [System.IO.Path]::GetPathRoot($Root)
if ($driveRoot -ne 'F:\') {
    throw "Portable export must run from F:\. Current path: $Root"
}

$exportDir = Join-Path $Root 'exports'
New-Item -ItemType Directory -Force -Path $exportDir | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stageDir = Join-Path $Root ".export-stage-$timestamp"
$stageRoot = Join-Path $stageDir 'euvd-sbom-matcher'
New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null

try {
    $exclude = @('exports', '.artifact-work', 'runtime-install', '__pycache__')
    if (-not $WithData) {
        $exclude += @('data', 'outputs')
    }

    Get-ChildItem -LiteralPath $Root -Force | Where-Object {
        $_.Name -notin $exclude -and $_.Name -notlike '.export-stage-*'
    } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $stageRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $stageRoot 'data'), (Join-Path $stageRoot 'outputs') | Out-Null
    if ($WithData) {
        $sourceDb = Join-Path $Root 'data\workbench.sqlite3'
        $stagedDb = Join-Path $stageRoot 'data\workbench.sqlite3'
        if (Test-Path -LiteralPath $sourceDb) {
            if (-not (Test-Path -LiteralPath $RuntimePython)) {
                throw 'Portable Python runtime is required for a consistent SQLite backup.'
            }
            Remove-Item -LiteralPath $stagedDb -Force -ErrorAction SilentlyContinue
            & $RuntimePython -c 'import sqlite3,sys; source=sqlite3.connect(sys.argv[1]); target=sqlite3.connect(sys.argv[2]); source.backup(target); target.close(); source.close()' $sourceDb $stagedDb
            if ($LASTEXITCODE -ne 0) {
                throw 'SQLite online backup failed.'
            }
            Remove-Item -LiteralPath "$stagedDb-wal", "$stagedDb-shm" -Force -ErrorAction SilentlyContinue
        }
    }
    $zipName = "euvd-sbom-matcher-portable-$timestamp.zip"
    $zipPath = Join-Path $exportDir $zipName
    Compress-Archive -LiteralPath $stageRoot -DestinationPath $zipPath -CompressionLevel Optimal

    Write-Host "Portable package created: $zipPath"
    if ($WithData) {
        Write-Host 'The package includes cache, uploads, jobs, and generated reports.'
    } else {
        Write-Host 'The package contains the application only. Local customer data was excluded.'
    }
} finally {
    if (Test-Path -LiteralPath $stageDir) {
        $resolvedStage = (Resolve-Path -LiteralPath $stageDir).Path
        if ($resolvedStage.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
