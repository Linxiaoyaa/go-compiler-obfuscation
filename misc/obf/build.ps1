param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$Pattern = "",
    [string]$Seed = "",
    [string]$Cache = "",
    [string[]]$ScanPlaintext = @(),
    [switch]$NoObfuscateNames,
    [switch]$KeepPclnNames,
    [switch]$NoObfuscateEntryOff,
    [switch]$NoObfuscateMagic,
    [switch]$KeepSymbols
)

$ErrorActionPreference = "Stop"

function Find-ByteSequence {
    param(
        [byte[]]$Data,
        [byte[]]$Needle
    )

    if ($Needle.Length -eq 0) {
        return -1
    }
    $limit = $Data.Length - $Needle.Length
    for ($i = 0; $i -le $limit; $i++) {
        if ($Data[$i] -ne $Needle[0]) {
            continue
        }
        $match = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Data[$i + $j] -ne $Needle[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $i
        }
    }
    return -1
}

function Get-ObfEntryKey {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    } finally {
        $sha.Dispose()
    }
    $key = [uint64][BitConverter]::ToUInt32($digest, 0)
    $key = $key -bor [uint64]1
    if ($key -eq 0 -or $key -eq [uint64]2779096485) {
        $key = [uint64]0x6d2b79f5
    }
    return [uint64]$key
}

function Get-ObfPclnMagic {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("pcln-magic/" + $Value))
    } finally {
        $sha.Dispose()
    }
    $magic = [uint64][BitConverter]::ToUInt32($digest, 0)
    if ($magic -eq 0 -or $magic -eq [uint64]2779096485 -or $magic -eq [uint64]4294967291 -or $magic -eq [uint64]4294967290 -or $magic -eq [uint64]4294967280 -or $magic -eq [uint64]4294967281) {
        $magic = [uint64]305419901
    }
    return $magic
}

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
    $Cache = Join-Path $env:LOCALAPPDATA "go-build-obf-v8"
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

    $nameFlag = if ($NoObfuscateNames) { "" } else { ",obfnames=1" }
    $gcflags = "$Pattern=-d=obfseed=$Seed,obfreport=1$nameFlag"
    $args = @("build", "-trimpath", "-gcflags=$gcflags", "-o", $outPath)

    $ldflags = @()
    if (-not $KeepSymbols) {
        $ldflags += @("-s", "-w", "-buildid=")
    }
    $hidePclnNames = -not $NoObfuscateNames -and -not $KeepPclnNames
    if ($hidePclnNames) {
        $ldflags += "-obfpclnnames"
    }
    if (-not $NoObfuscateEntryOff) {
        $entryKey = Get-ObfEntryKey -Value $Seed
        $ldflags += @("-obfentryoff", "-obfentrykey=$entryKey")
    }
    if (-not $NoObfuscateMagic) {
        $magic = Get-ObfPclnMagic -Value $Seed
        $ldflags += @("-obfmagic", "-obfmagicvalue=$magic")
    }
    if ($ldflags.Count -gt 0) {
        $args += "-ldflags=$($ldflags -join ' ')"
    }
    $args += $Package

    Write-Host "compiler: $go"
    Write-Host "pattern:  $Pattern"
    Write-Host "seed:     $Seed"
    Write-Host "cache:    $Cache"
    $nameMode = if ($NoObfuscateNames) { "stable" } elseif ($KeepPclnNames) { "hashed-protected" } else { "hidden-protected" }
    Write-Host "names:    $nameMode"
    Write-Host "pclntab:  $(if ($NoObfuscateMagic) { 'standard-magic' } else { 'seed-magic' })"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    & $go @args
    $stopwatch.Stop()
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $artifact = Get-Item -LiteralPath $outPath
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $outPath
    if ($ScanPlaintext.Count -gt 0) {
        $artifactBytes = [System.IO.File]::ReadAllBytes($outPath)
        foreach ($literal in $ScanPlaintext) {
            if ([string]::IsNullOrEmpty($literal)) {
                throw "ScanPlaintext entries must be non-empty"
            }
            $needle = [System.Text.Encoding]::UTF8.GetBytes($literal)
            $offset = Find-ByteSequence -Data $artifactBytes -Needle $needle
            if ($offset -ge 0) {
                throw "Plaintext scan matched at file offset $offset"
            }
        }
        Write-Host "scan:     $($ScanPlaintext.Count) plaintext value(s) absent"
    }
    Write-Host "output:   $($artifact.FullName)"
    Write-Host "size:     $($artifact.Length)"
    Write-Host "sha256:   $($hash.Hash)"
    Write-Host ("elapsed:  {0:N3}s" -f $stopwatch.Elapsed.TotalSeconds)
} finally {
    $env:GOROOT = $oldGOROOT
    $env:GOCACHE = $oldGOCACHE
    $env:GOTOOLCHAIN = $oldGOTOOLCHAIN
}
