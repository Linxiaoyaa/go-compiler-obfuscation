param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$Pattern = "",
    [string]$Seed = "",
    [string]$Cache = "",
    [string]$Report = "",
    [string[]]$ScanPlaintext = @(),
    [switch]$NoObfuscateNames,
    [switch]$KeepPclnNames,
    [switch]$NoObfuscateEntryOff,
    [switch]$NoObfuscateMagic,
    [switch]$NoRandomizeLayout,
    [switch]$NoObfuscateFileNames,
    [switch]$KeepSymbols
)

$ErrorActionPreference = "Stop"

function Resolve-UserPath {
    param([string]$Value)

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path ([string](Get-Location).Path) $Value))
}

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

function Find-ByteSequenceCount {
    param(
        [byte[]]$Data,
        [byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Data.Length -lt $Needle.Length) {
        return 0
    }
    $count = 0
    $limit = $Data.Length - $Needle.Length
    for ($i = 0; $i -le $limit; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Data[$i + $j] -ne $Needle[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $count++
        }
    }
    return $count
}

function Get-Sha256Text {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace("-", "")).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Convert-BytesToHex {
    param([byte[]]$Value)

    return ([BitConverter]::ToString($Value).Replace("-", "")).ToLowerInvariant()
}

function Get-LittleEndianBytes {
    param(
        [uint64]$Value,
        [int]$Width = 8
    )

    $full = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($full)
    }
    $result = New-Object byte[] $Width
    [Array]::Copy($full, 0, $result, 0, $Width)
    return $result
}

function Convert-GoQuotedString {
    param([string]$Value)

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $ch = $Value[$i]
        if ($ch -ne '\' -or $i + 1 -ge $Value.Length) {
            [void]$builder.Append($ch)
            continue
        }
        $i++
        $esc = $Value[$i]
        switch ($esc) {
            'a' { [void]$builder.Append([char]7) }
            'b' { [void]$builder.Append([char]8) }
            'f' { [void]$builder.Append([char]12) }
            'n' { [void]$builder.Append("`n") }
            'r' { [void]$builder.Append("`r") }
            't' { [void]$builder.Append("`t") }
            'v' { [void]$builder.Append([char]11) }
            '\' { [void]$builder.Append('\') }
            '"' { [void]$builder.Append('"') }
            'x' {
                if ($i + 2 -lt $Value.Length) {
                    $hex = $Value.Substring($i + 1, 2)
                    $number = 0
                    if ([int]::TryParse($hex, [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
                        [void]$builder.Append([char]$number)
                        $i += 2
                    } else {
                        [void]$builder.Append($esc)
                    }
                } else {
                    [void]$builder.Append($esc)
                }
            }
            'u' {
                if ($i + 4 -lt $Value.Length) {
                    $hex = $Value.Substring($i + 1, 4)
                    $number = 0
                    if ([int]::TryParse($hex, [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
                        [void]$builder.Append([char]$number)
                        $i += 4
                    } else {
                        [void]$builder.Append($esc)
                    }
                } else {
                    [void]$builder.Append($esc)
                }
            }
            'U' {
                if ($i + 8 -lt $Value.Length) {
                    $hex = $Value.Substring($i + 1, 8)
                    $number = 0
                    if ([int]::TryParse($hex, [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
                        try {
                            [void]$builder.Append([char]::ConvertFromUtf32($number))
                            $i += 8
                        } catch {
                            [void]$builder.Append($esc)
                        }
                    } else {
                        [void]$builder.Append($esc)
                    }
                } else {
                    [void]$builder.Append($esc)
                }
            }
            default { [void]$builder.Append($esc) }
        }
    }
    return $builder.ToString()
}

function Parse-ObfReportLine {
    param([string]$Line)

    $pattern = '^OBFREPORT function="(?<function>(?:\\.|[^"])*)" requested="(?<requested>(?:\\.|[^"])*)" applied="(?<applied>(?:\\.|[^"])*)"$'
    $match = [System.Text.RegularExpressions.Regex]::Match($Line, $pattern)
    if (-not $match.Success) {
        return $null
    }
    return [pscustomobject]@{
        function = Convert-GoQuotedString $match.Groups['function'].Value
        requested = Convert-GoQuotedString $match.Groups['requested'].Value
        applied = Convert-GoQuotedString $match.Groups['applied'].Value
        raw = $Line
    }
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

function Get-ObfLayoutSeed {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("layout/" + $Value))
    } finally {
        $sha.Dispose()
    }
    $seed = [uint64][BitConverter]::ToUInt64($digest, 0)
    $seed = $seed % [uint64]9223372036854775807
    if ($seed -eq 0) {
        $seed = [uint64]1
    }
    return $seed
}

function Get-ObfFileNameKey {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("filetab/" + $Value))
    } finally {
        $sha.Dispose()
    }
    $key = [uint64][BitConverter]::ToUInt64($digest, 0)
    if ($key -eq 0) {
        $key = [uint64]1
    }
    return $key
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
    $Cache = Join-Path $env:LOCALAPPDATA "go-build-obf-v10"
}
$Cache = Resolve-UserPath -Value $Cache
New-Item -ItemType Directory -Path $Cache -Force | Out-Null

$oldGOROOT = $env:GOROOT
$oldGOCACHE = $env:GOCACHE
$oldGOTOOLCHAIN = $env:GOTOOLCHAIN
$temporaryReport = $null
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

    $outPath = Resolve-UserPath -Value $Out
    $outDir = Split-Path -Parent $outPath
    if ($outDir) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $reportPath = $null
    if ($Report) {
        $reportPath = Resolve-UserPath -Value $Report
        if ([StringComparer]::OrdinalIgnoreCase.Equals($reportPath, $outPath)) {
            throw "Report path must differ from artifact path"
        }
        $reportDir = Split-Path -Parent $reportPath
        if ($reportDir) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }
        if (Test-Path -LiteralPath $reportPath) {
            Remove-Item -LiteralPath $reportPath -Force
        }
    }

    $nameFlag = if ($NoObfuscateNames) { "" } else { ",obfnames=1" }
    $gcflags = "$Pattern=-d=obfseed=$Seed,obfreport=1$nameFlag"
    $args = @("build", "-trimpath", "-gcflags=$gcflags", "-o", $outPath)

    $entryKey = $null
    $magic = $null
    $layoutSeed = $null
    $fileNameKey = $null
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
    if (-not $NoRandomizeLayout) {
        $layoutSeed = Get-ObfLayoutSeed -Value $Seed
        $ldflags += "-randlayout=$layoutSeed"
    }
    if (-not $NoObfuscateFileNames) {
        $fileNameKey = Get-ObfFileNameKey -Value $Seed
        $ldflags += @("-obffilenames", "-obffilenamekey=$fileNameKey")
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
    Write-Host "layout:   $(if ($NoRandomizeLayout) { 'stable' } else { 'seed-randomized' })"
    Write-Host "files:    $(if ($NoObfuscateFileNames) { 'original' } else { 'hashed-pclntab' })"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $oldErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $buildOutput = @(& $go @args 2>&1)
        $buildExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    $stopwatch.Stop()
    $obfReports = @()
    foreach ($lineObject in $buildOutput) {
        $line = [string]$lineObject
        if ($line.Length -gt 0) {
            Write-Host $line
            $parsed = Parse-ObfReportLine -Line $line
            if ($null -ne $parsed) {
                $obfReports += $parsed
            }
        }
    }
    if ($buildExitCode -ne 0) {
        exit $buildExitCode
    }

    $artifact = Get-Item -LiteralPath $outPath
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $outPath
    $artifactBytes = $null
    if ($Report -or $ScanPlaintext.Count -gt 0) {
        $artifactBytes = [System.IO.File]::ReadAllBytes($outPath)
    }
    $scanResults = @()
    if ($ScanPlaintext.Count -gt 0) {
        foreach ($literal in $ScanPlaintext) {
            if ([string]::IsNullOrEmpty($literal)) {
                throw "ScanPlaintext entries must be non-empty"
            }
            $needle = [System.Text.Encoding]::UTF8.GetBytes($literal)
            $offset = Find-ByteSequence -Data $artifactBytes -Needle $needle
            $scanResults += [pscustomobject]@{
                sha256 = Get-Sha256Text -Value $literal
                length = $needle.Length
                encoding = "utf-8"
                present = ($offset -ge 0)
                offset = $offset
            }
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

    if ($reportPath) {
        $protectedPrefix = "obf.fn."
        $sourcePrefix = "obf.src."
        $protectedPrefixCount = Find-ByteSequenceCount -Data $artifactBytes -Needle ([System.Text.Encoding]::UTF8.GetBytes($protectedPrefix))
        $sourcePrefixCount = Find-ByteSequenceCount -Data $artifactBytes -Needle ([System.Text.Encoding]::UTF8.GetBytes($sourcePrefix))
        $standardMagicValues = @([uint32]4294967291, [uint32]4294967290, [uint32]4294967280, [uint32]4294967281)
        $magicKind = if ($NoObfuscateMagic) { "standard" } else { "seed-derived" }
        $magicValueForProfile = $null
        $magicBytesForProfile = $null
        $magicOffsetForProfile = -1
        if (-not $NoObfuscateMagic) {
            $magicValueForProfile = [uint32]$magic
            $magicBytes = Get-LittleEndianBytes -Value $magicValueForProfile -Width 4
            $magicBytesForProfile = Convert-BytesToHex -Value $magicBytes
            $magicOffsetForProfile = Find-ByteSequence -Data $artifactBytes -Needle $magicBytes
        } else {
            foreach ($candidate in $standardMagicValues) {
                $candidateBytes = Get-LittleEndianBytes -Value $candidate -Width 4
                $candidateOffset = Find-ByteSequence -Data $artifactBytes -Needle $candidateBytes
                if ($candidateOffset -ge 0 -and ($magicOffsetForProfile -lt 0 -or $candidateOffset -lt $magicOffsetForProfile)) {
                    $magicValueForProfile = $candidate
                    $magicBytesForProfile = Convert-BytesToHex -Value $candidateBytes
                    $magicOffsetForProfile = $candidateOffset
                }
            }
        }
        $entryKeyBytesForProfile = $null
        $entryKeyCount = 0
        if (-not $NoObfuscateEntryOff) {
            $entryKeyBytes = Get-LittleEndianBytes -Value ([uint64]$entryKey) -Width 4
            $entryKeyBytesForProfile = Convert-BytesToHex -Value $entryKeyBytes
            $entryKeyCount = Find-ByteSequenceCount -Data $artifactBytes -Needle $entryKeyBytes
        }
        $compilerVersion = ""
        try {
            $versionOutput = @(& $go version 2>$null)
            if ($versionOutput.Count -gt 0) {
                $compilerVersion = ([string]$versionOutput[0]).Trim()
            }
        } catch {
            $compilerVersion = ""
        }
        $profile = [ordered]@{
            schema = "go-obf-profile/v1"
            version = 1
            generatedAtUtc = [DateTime]::UtcNow.ToString("o")
            compiler = [ordered]@{
                path = [System.IO.Path]::GetFullPath($go)
                version = $compilerVersion
            }
            build = [ordered]@{
                package = $Package
                pattern = $Pattern
                output = $artifact.FullName
                cache = $Cache
                seed = [ordered]@{
                    algorithm = "sha256"
                    domain = "go-obf-seed-v1"
                    fingerprint = Get-Sha256Text -Value ("go-obf-seed-v1/" + $Seed)
                }
                symbols = if ($KeepSymbols) { "kept" } else { "stripped" }
            }
            protection = [ordered]@{
                names = $nameMode
                pclntabNames = if ($NoObfuscateNames) { "original" } elseif ($KeepPclnNames) { "hashed-protected" } else { "hidden-protected" }
                entryOffsets = if ($NoObfuscateEntryOff) { "raw" } else { "encoded" }
                pclntabMagic = $magicKind
                functionLayout = if ($NoRandomizeLayout) { "stable" } else { "seed-randomized" }
                fileNames = if ($NoObfuscateFileNames) { "original" } else { "hashed-pclntab" }
                stringRuntime = "v2"
                vm = "v3"
            }
            artifact = [ordered]@{
                path = $artifact.FullName
                size = [int64]$artifact.Length
                sha256 = $hash.Hash.ToLowerInvariant()
                elapsedSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            }
            plaintextScans = @($scanResults)
            obfReport = [ordered]@{
                count = @($obfReports).Count
                functions = @($obfReports | ForEach-Object {
                    [ordered]@{
                        name = $_.function
                        requested = $_.requested
                        applied = $_.applied
                    }
                })
            }
            markers = [ordered]@{
                protectedNamePrefix = $protectedPrefix
                protectedNameCount = $protectedPrefixCount
                sourcePrefix = $sourcePrefix
                sourceNameCount = $sourcePrefixCount
                pclntabMagic = [ordered]@{
                    kind = $magicKind
                    value = if ($null -eq $magicValueForProfile) { $null } else { [uint32]$magicValueForProfile }
                    littleEndian = $magicBytesForProfile
                    offset = $magicOffsetForProfile
                }
                entryKey = [ordered]@{
                    enabled = (-not $NoObfuscateEntryOff)
                    littleEndian = $entryKeyBytesForProfile
                    count = $entryKeyCount
                }
            }
        }
        $json = $profile | ConvertTo-Json -Depth 12
        $temporaryReport = "$reportPath.tmp.$PID"
        Set-Content -LiteralPath $temporaryReport -Value $json -Encoding UTF8
        Move-Item -LiteralPath $temporaryReport -Destination $reportPath -Force
        $temporaryReport = $null
        Write-Host "report:   $reportPath"
    }
} finally {
    if ($temporaryReport -and (Test-Path -LiteralPath $temporaryReport)) {
        Remove-Item -LiteralPath $temporaryReport -Force -ErrorAction SilentlyContinue
    }
    $env:GOROOT = $oldGOROOT
    $env:GOCACHE = $oldGOCACHE
    $env:GOTOOLCHAIN = $oldGOTOOLCHAIN
}
