$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$RuntimeDir = Join-Path $Root 'runtime'
$RuntimePython = Join-Path $RuntimeDir 'python.exe'
$ReadyMarker = Join-Path $RuntimeDir 'READY'
$PythonVersion = '3.13.14'
$PythonSha256 = '90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907'
$PipVersion = '26.2.1'
$PipZipAppSha256 = '91d5fd9f6f25549fd839c60536c6f1b945316ce3588d34a605635b6071c91526'
$RequirementsLock = Join-Path $Root 'requirements.lock'
$RequirementsLockSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $RequirementsLock).Hash.ToLowerInvariant()

if ((Test-Path $RuntimePython) -and (Test-Path $ReadyMarker)) {
    $readyLines = Get-Content -LiteralPath $ReadyMarker
    $readyMatches = `
        ($readyLines -contains "Python $PythonVersion") -and `
        ($readyLines -contains "Requirements-Lock-SHA256 $RequirementsLockSha256")
    & $RuntimePython -c 'import charset_normalizer, fastapi, httpx, openpyxl, packaging, multipart, uvicorn'
    if ($readyMatches -and ($LASTEXITCODE -eq 0)) {
        Write-Host 'Portable runtime is ready.'
        exit 0
    }
}

$stageDir = Join-Path $Root 'runtime-install'
$stagePython = Join-Path $stageDir 'python'
$archivePath = Join-Path $stageDir "python-$PythonVersion-embed-amd64.zip"
$pipZipAppPath = Join-Path $stageDir "pip-$PipVersion.pyz"

if (Test-Path $stageDir) {
    $resolvedStage = (Resolve-Path $stageDir).Path
    if (-not $resolvedStage.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe runtime staging path: $resolvedStage"
    }
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $stagePython | Out-Null

try {
    $pythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
    Write-Host "Downloading portable Python $PythonVersion..."
    Invoke-WebRequest -Uri $pythonUrl -OutFile $archivePath -UseBasicParsing

    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $PythonSha256) {
        throw "Python archive checksum mismatch. Expected $PythonSha256, got $actualHash."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $stagePython -Force

    $pthPath = Get-ChildItem -LiteralPath $stagePython -Filter 'python*._pth' | Select-Object -First 1
    if (-not $pthPath) {
        throw 'Python path configuration was not found.'
    }
    $pthContent = (Get-Content -LiteralPath $pthPath.FullName) -replace '^#import site$', 'import site'
    [System.IO.File]::WriteAllLines($pthPath.FullName, $pthContent, [System.Text.UTF8Encoding]::new($false))

    Write-Host 'Installing application dependencies...'
    $pipZipAppUrl = "https://bootstrap.pypa.io/pip/zipapp/pip-$PipVersion.pyz"
    Invoke-WebRequest -Uri $pipZipAppUrl -OutFile $pipZipAppPath -UseBasicParsing
    $actualPipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pipZipAppPath).Hash.ToLowerInvariant()
    if ($actualPipHash -ne $PipZipAppSha256) {
        throw "pip zipapp checksum mismatch. Expected $PipZipAppSha256, got $actualPipHash."
    }

    & (Join-Path $stagePython 'python.exe') $pipZipAppPath install `
        --disable-pip-version-check `
        --no-warn-script-location `
        --require-hashes `
        -r $RequirementsLock
    if ($LASTEXITCODE -ne 0) {
        throw 'Application dependency installation failed.'
    }

    & (Join-Path $stagePython 'python.exe') -c 'import charset_normalizer, fastapi, httpx, openpyxl, packaging, multipart, uvicorn'
    if ($LASTEXITCODE -ne 0) {
        throw 'Portable runtime verification failed.'
    }

    [System.IO.File]::WriteAllText(
        (Join-Path $stagePython 'READY'),
        "Python $PythonVersion`r`nRequirements-Lock-SHA256 $RequirementsLockSha256`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    if (Test-Path $RuntimeDir) {
        $resolvedRuntime = (Resolve-Path $RuntimeDir).Path
        if (-not $resolvedRuntime.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe runtime path: $resolvedRuntime"
        }
        Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force
    }
    Move-Item -LiteralPath $stagePython -Destination $RuntimeDir
    Write-Host "Portable runtime installed: $RuntimeDir"
} finally {
    if (Test-Path $stageDir) {
        $resolvedStage = (Resolve-Path $stageDir).Path
        if ($resolvedStage.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
