param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$Pattern = "",
    [string]$Seed = "",
    [string]$SeedFile = "",
    [string]$SeedEnv = "GO_OBF_SEED",
    [string]$Cache = "",
    [string]$Report = "",
    [string]$Manifest = "",
    [int]$VMBudget = 2048,
    [string[]]$ScanPlaintext = @(),
    [string[]]$ScanMetadata = @(),
    [switch]$NoDefaultMetadataScan,
    [switch]$NoObfuscateNames,
    [switch]$KeepPclnNames,
    [switch]$NoObfuscateEntryOff,
    [switch]$NoObfuscateMagic,
    [switch]$NoRuntimeChecks,
    [switch]$NoRandomizeLayout,
    [switch]$NoObfuscateFileNames,
    [switch]$KeepSymbols,
    [switch]$ShowSeed
)

$ErrorActionPreference = "Stop"

function Resolve-UserPath {
    param([string]$Value)

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path ([string](Get-Location).Path) $Value))
}

function Get-GitRevision {
    param([string]$Directory)

    try {
        $value = @(& git -C $Directory rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $value.Count -gt 0) {
            return ([string]$value[0]).Trim()
        }
    } catch {
    }
    return ""
}

function Get-GitDirty {
    param([string]$Directory)

    try {
        $value = @(& git -C $Directory status --porcelain --untracked-files=no 2>$null)
        return $LASTEXITCODE -eq 0 -and $value.Count -gt 0
    } catch {
        return $null
    }
}

function Get-CompilerSourceFiles {
    param([string]$Directory)

    $prefixes = @(
        "src/cmd/compile/",
        "src/cmd/internal/",
        "src/cmd/link/",
        "src/internal/abi/",
        "src/internal/buildcfg/",
        "src/internal/goarch/",
        "src/internal/objabi/",
        "src/internal/pkgbits/",
        "src/internal/platform/",
        "src/internal/runtime/",
        "src/runtime/"
    )
    $files = @(& git -C $Directory ls-files --cached --others --exclude-standard -- "src" 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed for compiler source root: $Directory"
    }
    return @($files | ForEach-Object { ([string]$_).Replace("\", "/") } | Where-Object {
        $candidate = $_
        @($prefixes | Where-Object { $candidate.StartsWith($_, [System.StringComparison]::Ordinal) }).Count -gt 0
    } | Sort-Object -Unique)
}

function Get-TrackedSourceDigest {
    param(
        [string]$Directory,
        [string[]]$Files
    )

    $incremental = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        foreach ($relative in @($Files | Sort-Object -Unique)) {
            $normalized = ([string]$relative).Replace("\", "/")
            $path = [System.IO.Path]::GetFullPath((Join-Path $Directory $normalized))
            $prefix = [System.IO.Path]::GetFullPath($Directory).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
            if (-not $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "source digest path escapes compiler root: $normalized"
            }
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "tracked compiler source file is missing: $normalized"
            }
            $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
            $lengthBytes = [BitConverter]::GetBytes([uint64]$nameBytes.Length)
            if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($lengthBytes) }
            $incremental.AppendData($lengthBytes)
            $incremental.AppendData($nameBytes)
            $content = [System.IO.File]::ReadAllBytes($path)
            $contentLengthBytes = [BitConverter]::GetBytes([uint64]$content.Length)
            if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($contentLengthBytes) }
            $incremental.AppendData($contentLengthBytes)
            $incremental.AppendData($content)
        }
        return Convert-BytesToHex -Value $incremental.GetHashAndReset()
    } finally {
        $incremental.Dispose()
    }
}

function Get-SeedFromFile {
    param([string]$Path)

    $value = [System.IO.File]::ReadAllText($Path).Trim()
    if ([string]::IsNullOrEmpty($value)) {
        throw "SeedFile is empty: $Path"
    }
    return $value
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

function Get-ObfRuntimeGuardV2Seal {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $input = "go-obf-runtime-guard-v2/bootstrap" + [char]0 + $Value
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($input))
    } finally {
        $sha.Dispose()
    }
    $seal = [uint64][BitConverter]::ToUInt64($digest, 0)
    $unpatched = [Convert]::ToUInt64("a5a5a5a5a5a5a5a5", 16)
    if ($seal -eq 0 -or $seal -eq $unpatched) {
        $seal = [Convert]::ToUInt64("6a09e667f3bcc909", 16)
    }
    return $seal
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

$seedSource = if ($Seed) { "parameter" } else { "generated" }
if ($Seed -and $SeedFile) {
    throw "Seed and SeedFile are mutually exclusive"
}
if ($SeedEnv -and $SeedEnv -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
    throw "SeedEnv must be a valid environment variable name"
}
if ($SeedFile) {
    $seedPath = Resolve-UserPath -Value $SeedFile
    if (-not (Test-Path -LiteralPath $seedPath -PathType Leaf)) {
        throw "SeedFile does not exist: $seedPath"
    }
    $Seed = Get-SeedFromFile -Path $seedPath
    $seedSource = "file"
} elseif (-not $Seed -and $SeedEnv) {
    $environmentSeed = [Environment]::GetEnvironmentVariable($SeedEnv, "Process")
    if ($environmentSeed) {
        $Seed = $environmentSeed.Trim()
        $seedSource = "environment:$SeedEnv"
    }
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
$seedFingerprint = Get-Sha256Text -Value ("go-obf-seed-v1/" + $Seed)

if (-not $Cache) {
    $Cache = Join-Path $env:LOCALAPPDATA "go-build-obf-v12"
}
$Cache = Resolve-UserPath -Value $Cache
New-Item -ItemType Directory -Path $Cache -Force | Out-Null

$oldGOROOT = $env:GOROOT
$oldGOCACHE = $env:GOCACHE
$oldGOTOOLCHAIN = $env:GOTOOLCHAIN
$oldObfSeed = $env:GO_OBF_SEED
$temporaryOut = $null
$temporaryReport = $null
$temporaryManifest = $null
$artifactBackup = $null
$reportBackup = $null
$manifestBackup = $null
$publishedArtifactWasNew = $false
$publishedReportWasNew = $false
$publishedManifestWasNew = $false
try {
    $env:GOROOT = $root
    $env:GOCACHE = $Cache
    $env:GOTOOLCHAIN = "local"
    $env:GO_OBF_SEED = $Seed

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
    }
    $manifestPath = $null
    if ($Manifest) {
        if (-not $reportPath) {
            throw "Manifest requires Report so the release record can bind both files"
        }
        $manifestPath = Resolve-UserPath -Value $Manifest
        if ([StringComparer]::OrdinalIgnoreCase.Equals($manifestPath, $outPath) -or
            [StringComparer]::OrdinalIgnoreCase.Equals($manifestPath, $reportPath)) {
            throw "Manifest path must differ from artifact and report paths"
        }
        $manifestDir = Split-Path -Parent $manifestPath
        if ($manifestDir) {
            New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
        }
    }

    $temporaryOut = "$outPath.tmp.$PID"
    if (Test-Path -LiteralPath $temporaryOut) {
        Remove-Item -LiteralPath $temporaryOut -Force
    }

    $nameFlag = if ($NoObfuscateNames) { "" } else { ",obfnames=1" }
    # The guard binds compiler-generated seals to both linker-patched runtime
    # fields. Diagnostic builds that retain either raw field intentionally do
    # not receive a guard unless they restore the normal protected layout.
    $runtimeChecksEnabled = -not $NoRuntimeChecks -and -not $NoObfuscateEntryOff -and -not $NoObfuscateMagic
    $runtimeCheckFlag = if ($runtimeChecksEnabled) { ",obfruntimecheck=1" } else { "" }
    if ($VMBudget -lt 256) {
        throw "VMBudget must be at least 256"
    }
    $gcflags = "$Pattern=-d=obfseedenv=GO_OBF_SEED,obfseedid=$seedFingerprint,obfv4budget=$VMBudget,obfreport=1$nameFlag$runtimeCheckFlag"
    $args = @("build", "-trimpath", "-gcflags=$gcflags", "-o", $temporaryOut)

    $entryKey = $null
    $magic = $null
    $bootstrapSeal = $null
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
    if ($runtimeChecksEnabled) {
        $bootstrapSeal = Get-ObfRuntimeGuardV2Seal -Value $Seed
        $ldflags += @("-obfguardv2", "-obfguardv2seal=$bootstrapSeal")
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
    Write-Host "seed:     fingerprint=$seedFingerprint"
    Write-Host "seed-source: $seedSource"
    if ($ShowSeed) {
        Write-Host "seed-value: $Seed"
    }
    Write-Host "cache:    $Cache"
    $nameMode = if ($NoObfuscateNames) { "stable" } elseif ($KeepPclnNames) { "hashed-protected" } else { "hidden-protected" }
    Write-Host "names:    $nameMode"
    Write-Host "pclntab:  $(if ($NoObfuscateMagic) { 'standard-magic' } else { 'seed-magic' })"
    Write-Host "runtime:  $(if ($runtimeChecksEnabled) { 'entry-integrity-v2' } else { 'disabled' })"
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

    $artifactBytes = $null
    if ($Report -or $ScanPlaintext.Count -gt 0 -or $ScanMetadata.Count -gt 0 -or -not $NoDefaultMetadataScan) {
        $artifactBytes = [System.IO.File]::ReadAllBytes($temporaryOut)
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
    $defaultMetadataValues = @()
    if (-not $NoDefaultMetadataScan) {
        $defaultMetadataValues = @($Seed, $root, ([string](Get-Location).Path))
    }
    $metadataScanValues = @(@($defaultMetadataValues) + @($ScanMetadata) | Where-Object { -not [string]::IsNullOrEmpty([string]$_) } | Select-Object -Unique)
    $metadataScanResults = @()
    foreach ($metadataValue in $metadataScanValues) {
        $metadataString = [string]$metadataValue
        $needle = [System.Text.Encoding]::UTF8.GetBytes($metadataString)
        $offset = Find-ByteSequence -Data $artifactBytes -Needle $needle
        $metadataScanResults += [pscustomobject]@{
            sha256 = Get-Sha256Text -Value $metadataString
            length = $needle.Length
            encoding = "utf-8"
            present = ($offset -ge 0)
            offset = $offset
        }
        if ($offset -ge 0) {
            throw "Metadata scan matched at file offset $offset"
        }
    }
    if ($metadataScanValues.Count -gt 0) {
        Write-Host "metadata: $($metadataScanValues.Count) residual value(s) absent"
    }

    $temporaryArtifact = Get-Item -LiteralPath $temporaryOut
    $artifactLength = [int64]$temporaryArtifact.Length
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryOut

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
        $bootstrapSealBytesForProfile = $null
        $bootstrapSealCount = 0
        if ($runtimeChecksEnabled) {
            $bootstrapSealBytes = Get-LittleEndianBytes -Value ([uint64]$bootstrapSeal) -Width 8
            $bootstrapSealBytesForProfile = Convert-BytesToHex -Value $bootstrapSealBytes
            $bootstrapSealCount = Find-ByteSequenceCount -Data $artifactBytes -Needle $bootstrapSealBytes
        }
        $driverVersion = ""
        try {
            $versionOutput = @(& $go version 2>$null)
            if ($versionOutput.Count -gt 0) {
                $driverVersion = ([string]$versionOutput[0]).Trim()
            }
        } catch {
            $driverVersion = ""
        }
        $goToolDirOutput = @(& $go env GOTOOLDIR 2>$null)
        $goToolDir = if ($goToolDirOutput.Count -gt 0) { ([string]$goToolDirOutput[0]).Trim() } else { "" }
        $compilerName = if ($env:OS -eq "Windows_NT") { "compile.exe" } else { "compile" }
        $compilerPath = if ($goToolDir) { Join-Path $goToolDir $compilerName } else { "" }
        if (-not $compilerPath -or -not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
            throw "Go compiler executable was not found in GOTOOLDIR"
        }
        $compilerVersionOutput = @(& $go tool compile -V=full 2>$null)
        $compilerVersion = if ($compilerVersionOutput.Count -gt 0) { ([string]$compilerVersionOutput[0]).Trim() } else { "" }
        $compilerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $compilerPath).Hash.ToLowerInvariant()
        $driverHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $go).Hash.ToLowerInvariant()
        $compilerCommit = Get-GitRevision -Directory $root
        $compilerDirty = Get-GitDirty -Directory $root
        $compilerSourceFiles = Get-CompilerSourceFiles -Directory $root
        $compilerSourceDigest = Get-TrackedSourceDigest -Directory $root -Files $compilerSourceFiles
        $buildToolHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
        $verifyToolPath = Join-Path $PSScriptRoot "verify.ps1"
        $matrixToolPath = Join-Path $PSScriptRoot "test-matrix.ps1"
        $integrityToolPath = Join-Path $PSScriptRoot "test-integrity.ps1"
        $verifyToolHash = if (Test-Path -LiteralPath $verifyToolPath -PathType Leaf) { (Get-FileHash -Algorithm SHA256 -LiteralPath $verifyToolPath).Hash.ToLowerInvariant() } else { "" }
        $matrixToolHash = if (Test-Path -LiteralPath $matrixToolPath -PathType Leaf) { (Get-FileHash -Algorithm SHA256 -LiteralPath $matrixToolPath).Hash.ToLowerInvariant() } else { "" }
        $integrityToolHash = if (Test-Path -LiteralPath $integrityToolPath -PathType Leaf) { (Get-FileHash -Algorithm SHA256 -LiteralPath $integrityToolPath).Hash.ToLowerInvariant() } else { "" }
        $targetValues = @(& $go env GOOS GOARCH CGO_ENABLED 2>$null)
        $targetGoos = if ($targetValues.Count -gt 0) { ([string]$targetValues[0]).Trim() } else { "" }
        $targetGoarch = if ($targetValues.Count -gt 1) { ([string]$targetValues[1]).Trim() } else { "" }
        $targetCgo = if ($targetValues.Count -gt 2) { ([string]$targetValues[2]).Trim() } else { "" }
        $profile = [ordered]@{
            schema = "go-obf-profile/v2"
            version = 2
            generatedAtUtc = [DateTime]::UtcNow.ToString("o")
            compiler = [ordered]@{
                path = [System.IO.Path]::GetFullPath($compilerPath)
                version = $compilerVersion
                sha256 = $compilerHash
                commit = $compilerCommit
                dirty = $compilerDirty
                sourceRoot = $root
                source = [ordered]@{
                    algorithm = "sha256-length-prefixed-v1"
                    sha256 = $compilerSourceDigest
                    trackedFiles = $compilerSourceFiles.Count
                }
                driver = [ordered]@{
                    path = [System.IO.Path]::GetFullPath($go)
                    version = $driverVersion
                    sha256 = $driverHash
                }
            }
            tooling = [ordered]@{
                build = [ordered]@{ fileName = "build.ps1"; sha256 = $buildToolHash }
                verify = [ordered]@{ fileName = "verify.ps1"; sha256 = $verifyToolHash }
                matrix = [ordered]@{ fileName = "test-matrix.ps1"; sha256 = $matrixToolHash }
                integrity = [ordered]@{ fileName = "test-integrity.ps1"; sha256 = $integrityToolHash }
            }
            build = [ordered]@{
                package = $Package
                pattern = $Pattern
                output = $outPath
                cache = $Cache
                gcflags = $gcflags
                ldflags = ($ldflags -join " ")
                target = [ordered]@{
                    GOOS = $targetGoos
                    GOARCH = $targetGoarch
                    CGO_ENABLED = $targetCgo
                }
                seed = [ordered]@{
                    algorithm = "sha256"
                    domain = "go-obf-seed-v1"
                    fingerprint = $seedFingerprint
                    source = $seedSource
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
                stringRuntime = "v2+v3-ephemeral+v4-stream"
                vm = "v4-budgeted"
                runtimeChecks = if ($runtimeChecksEnabled) { "entry-v2" } else { "disabled" }
            }
            artifact = [ordered]@{
                path = $outPath
                size = $artifactLength
                sha256 = $hash.Hash.ToLowerInvariant()
                elapsedSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            }
            plaintextScans = @($scanResults)
            metadataScans = @($metadataScanResults)
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
                runtimeGuardV2 = [ordered]@{
                    enabled = $runtimeChecksEnabled
                    littleEndian = $bootstrapSealBytesForProfile
                    count = $bootstrapSealCount
                }
            }
        }
        $json = $profile | ConvertTo-Json -Depth 12
        $temporaryReport = "$reportPath.tmp.$PID"
        Set-Content -LiteralPath $temporaryReport -Value $json -Encoding UTF8
        if ($manifestPath) {
            $profileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryReport).Hash.ToLowerInvariant()
            $manifestObject = [ordered]@{
                schema = "go-obf-release-manifest/v1"
                version = 1
                artifact = [ordered]@{
                    fileName = [System.IO.Path]::GetFileName($outPath)
                    size = $artifactLength
                    sha256 = $hash.Hash.ToLowerInvariant()
                }
                profile = [ordered]@{
                    fileName = [System.IO.Path]::GetFileName($reportPath)
                    sha256 = $profileHash
                }
                compiler = [ordered]@{
                    sha256 = $compilerHash
                    commit = $compilerCommit
                    sourceSha256 = $compilerSourceDigest
                    sourceFiles = $compilerSourceFiles.Count
                    dirty = $compilerDirty
                }
                tooling = [ordered]@{
                    buildSha256 = $buildToolHash
                    verifySha256 = $verifyToolHash
                    matrixSha256 = $matrixToolHash
                    integritySha256 = $integrityToolHash
                }
                build = [ordered]@{
                    seedFingerprint = $seedFingerprint
                    GOOS = $targetGoos
                    GOARCH = $targetGoarch
                    CGO_ENABLED = $targetCgo
                }
                protection = [ordered]@{
                    runtimeChecks = if ($runtimeChecksEnabled) { "entry-v2" } else { "disabled" }
                }
            }
            $temporaryManifest = "$manifestPath.tmp.$PID"
            Set-Content -LiteralPath $temporaryManifest -Value ($manifestObject | ConvertTo-Json -Depth 8) -Encoding UTF8
        }
    }

    if (Test-Path -LiteralPath $outPath -PathType Leaf) {
        $artifactBackup = "$outPath.rollback.$PID"
        [System.IO.File]::Replace($temporaryOut, $outPath, $artifactBackup, $true)
    } else {
        [System.IO.File]::Move($temporaryOut, $outPath)
        $publishedArtifactWasNew = $true
    }
    $temporaryOut = $null
    try {
        if ($reportPath) {
            if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
                $reportBackup = "$reportPath.rollback.$PID"
                [System.IO.File]::Replace($temporaryReport, $reportPath, $reportBackup, $true)
            } else {
                [System.IO.File]::Move($temporaryReport, $reportPath)
                $publishedReportWasNew = $true
            }
            $temporaryReport = $null
        }
        if ($manifestPath) {
            if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
                $manifestBackup = "$manifestPath.rollback.$PID"
                [System.IO.File]::Replace($temporaryManifest, $manifestPath, $manifestBackup, $true)
            } else {
                [System.IO.File]::Move($temporaryManifest, $manifestPath)
                $publishedManifestWasNew = $true
            }
            $temporaryManifest = $null
        }
    } catch {
        if ($manifestBackup -and (Test-Path -LiteralPath $manifestBackup -PathType Leaf)) {
            $failedManifest = "$manifestPath.failed.$PID"
            [System.IO.File]::Replace($manifestBackup, $manifestPath, $failedManifest, $true)
            $manifestBackup = $null
            Remove-Item -LiteralPath $failedManifest -Force -ErrorAction SilentlyContinue
        } elseif ($publishedManifestWasNew -and $manifestPath -and (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            Remove-Item -LiteralPath $manifestPath -Force
        }
        if ($reportBackup -and (Test-Path -LiteralPath $reportBackup -PathType Leaf)) {
            $failedReport = "$reportPath.failed.$PID"
            [System.IO.File]::Replace($reportBackup, $reportPath, $failedReport, $true)
            $reportBackup = $null
            Remove-Item -LiteralPath $failedReport -Force -ErrorAction SilentlyContinue
        } elseif ($publishedReportWasNew -and $reportPath -and (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            Remove-Item -LiteralPath $reportPath -Force
        }
        if ($artifactBackup -and (Test-Path -LiteralPath $artifactBackup -PathType Leaf)) {
            $failedArtifact = "$outPath.failed.$PID"
            [System.IO.File]::Replace($artifactBackup, $outPath, $failedArtifact, $true)
            $artifactBackup = $null
            Remove-Item -LiteralPath $failedArtifact -Force -ErrorAction SilentlyContinue
        } elseif ($publishedArtifactWasNew -and (Test-Path -LiteralPath $outPath -PathType Leaf)) {
            Remove-Item -LiteralPath $outPath -Force
        }
        throw
    }

    if ($artifactBackup -and (Test-Path -LiteralPath $artifactBackup)) {
        Remove-Item -LiteralPath $artifactBackup -Force -ErrorAction SilentlyContinue
        $artifactBackup = $null
    }
    if ($reportBackup -and (Test-Path -LiteralPath $reportBackup)) {
        Remove-Item -LiteralPath $reportBackup -Force -ErrorAction SilentlyContinue
        $reportBackup = $null
    }
    if ($manifestBackup -and (Test-Path -LiteralPath $manifestBackup)) {
        Remove-Item -LiteralPath $manifestBackup -Force -ErrorAction SilentlyContinue
        $manifestBackup = $null
    }

    Write-Host "output:   $outPath"
    Write-Host "size:     $artifactLength"
    Write-Host "sha256:   $($hash.Hash)"
    Write-Host ("elapsed:  {0:N3}s" -f $stopwatch.Elapsed.TotalSeconds)
    if ($reportPath) {
        Write-Host "report:   $reportPath"
    }
    if ($manifestPath) {
        Write-Host "manifest: $manifestPath"
    }
} finally {
    if ($temporaryOut -and (Test-Path -LiteralPath $temporaryOut)) {
        Remove-Item -LiteralPath $temporaryOut -Force -ErrorAction SilentlyContinue
    }
    if ($temporaryReport -and (Test-Path -LiteralPath $temporaryReport)) {
        Remove-Item -LiteralPath $temporaryReport -Force -ErrorAction SilentlyContinue
    }
    if ($temporaryManifest -and (Test-Path -LiteralPath $temporaryManifest)) {
        Remove-Item -LiteralPath $temporaryManifest -Force -ErrorAction SilentlyContinue
    }
    $env:GOROOT = $oldGOROOT
    $env:GOCACHE = $oldGOCACHE
    $env:GOTOOLCHAIN = $oldGOTOOLCHAIN
    if ($null -eq $oldObfSeed) {
        Remove-Item Env:GO_OBF_SEED -ErrorAction SilentlyContinue
    } else {
        $env:GO_OBF_SEED = $oldObfSeed
    }
}
