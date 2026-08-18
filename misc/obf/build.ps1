param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$Pattern = "",
    [string]$Seed = "",
    [string]$Cache = "",
    [switch]$KeepSymbols
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$go = Join-Path $root "bin\go.exe"
if (-not (Test-Path -LiteralPath $go)) {
    throw "Custom Go compiler is not built: $go"
}

if (-not $Seed) {
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $Seed = -join ($bytes | ForEach-Object { $_.ToString("x2") })
}
if ($Seed -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Seed may contain only letters, digits, dot, underscore, and hyphen"
}

if (-not $Cache) {
    $Cache = Join-Path $env:LOCALAPPDATA "go-build-obf-v3"
}
$Cache = [System.IO.Path]::GetFullPath($Cache)
New-Item -ItemType Directory -Path $Cache -Force | Out-Null

$oldGOROOT = $env:GOROOT
$oldGOCACHE = $env:GOCACHE
$oldGOTOOLCHAIN = $env:GOTOOLCHAIN
try {
    $env:GOROOT = $root
    $env:GOCACHE = $Cache
    $env:GOTOOLCHAIN = "local"

    if (-not $Pattern) {
        $moduleLine = & $go list -m -f '{{.Path}}' 2>$null | Select-Object -First 1
        $module = if ($moduleLine) { ([string]$moduleLine).Trim() } else { "" }
        if ($LASTEXITCODE -eq 0 -and $module -and $module -ne "command-line-arguments") {
            $Pattern = "$module/..."
        } else {
            $Pattern = "command-line-arguments"
        }
    }

    $outPath = [System.IO.Path]::GetFullPath($Out)
    $outDir = Split-Path -Parent $outPath
    if ($outDir) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    $gcflags = "$Pattern=-d=obfseed=$Seed,obfreport=1"
    $args = @("build", "-trimpath", "-gcflags=$gcflags", "-o", $outPath)
    if (-not $KeepSymbols) {
        $args += @("-ldflags=-s -w -buildid=")
    }
    $args += $Package

    Write-Host "compiler: $go"
    Write-Host "pattern:  $Pattern"
    Write-Host "seed:     $Seed"
    Write-Host "cache:    $Cache"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    & $go @args
    $stopwatch.Stop()
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $artifact = Get-Item -LiteralPath $outPath
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $outPath
    Write-Host "output:   $($artifact.FullName)"
    Write-Host "size:     $($artifact.Length)"
    Write-Host "sha256:   $($hash.Hash)"
    Write-Host ("elapsed:  {0:N3}s" -f $stopwatch.Elapsed.TotalSeconds)
} finally {
    $env:GOROOT = $oldGOROOT
    $env:GOCACHE = $oldGOCACHE
    $env:GOTOOLCHAIN = $oldGOTOOLCHAIN
}
