param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$Profile,

    [string]$Manifest = "",
    [string]$ExpectedSha256 = "",
    [string]$ExpectedProfileSha256 = "",
    [string]$ExpectedManifestSha256 = "",
    [string]$ExpectedSeedFingerprint = "",
    [string]$ExpectedCompilerSha256 = "",
    [string]$ExpectedCompilerSourceSha256 = "",
    [string]$ExpectedCompilerCommit = "",
    [string]$CompilerPath = "",
    [string]$CompilerRoot = "",
    [switch]$RequireCompilerBinary,
    [switch]$RequireCompilerSource,
    [switch]$RequireTooling,
    [switch]$RequireCleanCompiler,
    [switch]$RequireRuntimeChecks,
    [switch]$RequireRuntimeGuardV3,
    [switch]$RequireStringV4,
    [switch]$RequireStringV5,
    [switch]$RequireCHeader,
    [string[]]$RequireFunction = @(),
    [int]$MinReportFunctions = -1,
    [int]$MinV4Aliases = -1,
    [switch]$RequireNativeCFG,
    [switch]$RequireNativeCFGFull,
    [string[]]$ForbiddenText = @(),
    [string[]]$ForbiddenMetadata = @(),
    [string[]]$ExpectedAbsent = @()
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

    if ($Needle.Length -eq 0 -or $Data.Length -lt $Needle.Length) {
        return -1
    }
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
        "src/cmd/compile/", "src/cmd/internal/", "src/cmd/link/",
        "src/internal/abi/", "src/internal/buildcfg/", "src/internal/goarch/",
        "src/internal/objabi/", "src/internal/pkgbits/", "src/internal/platform/",
        "src/internal/runtime/", "src/runtime/"
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

function Convert-HexToBytes {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value) -or ($Value.Length % 2) -ne 0 -or $Value -notmatch '^[0-9a-fA-F]+$') {
        return $null
    }
    $bytes = New-Object byte[] ($Value.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Value.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Add-Check {
    param(
        [string]$Name,
        [ValidateSet("pass", "fail", "skip")]
        [string]$Status,
        [object]$Expected = $null,
        [object]$Actual = $null,
        [string]$Detail = ""
    )

    [void]$checks.Add([ordered]@{
        name = $Name
        status = $Status
        expected = $Expected
        actual = $Actual
        detail = $Detail
    })
    if ($Status -eq "fail") {
        [void]$failures.Add($Name)
    }
}

function Emit-Result {
    param([int]$ExitCode)

    $result = [ordered]@{
        schema = "go-obf-verify/v1"
        ok = ($failures.Count -eq 0)
        artifact = $artifactPath
        profile = $profilePath
        profileSha256 = $profileFileHash
        checks = @($checks)
        failures = @($failures)
    }
    Write-Output ($result | ConvertTo-Json -Depth 12)
    exit $ExitCode
}

$checks = New-Object System.Collections.ArrayList
$failures = New-Object System.Collections.ArrayList
$artifactPath = Resolve-UserPath -Value $Artifact
$profilePath = Resolve-UserPath -Value $Profile
$manifestPath = if ($Manifest) { Resolve-UserPath -Value $Manifest } else { $null }
$profileObject = $null
$profileFileHash = $null
$manifestFileHash = $null
$manifestObject = $null
$artifactBytes = $null
$actualCompilerHash = ""
$actualCompilerSourceHash = ""
$actualCompilerCommit = ""
$actualCompilerDirty = $null

if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
    Add-Check -Name "profile.exists" -Status "fail" -Expected $true -Actual $false -Detail "profile file does not exist"
    Emit-Result -ExitCode 2
}

$profileFileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $profilePath).Hash.ToLowerInvariant()
if ($ExpectedProfileSha256) {
    $expectedProfileHashValid = $ExpectedProfileSha256 -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "external.profile-sha256.format" -Status $(if ($expectedProfileHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedProfileSha256
    if ($expectedProfileHashValid) {
        Add-Check -Name "external.profile-sha256" -Status $(if ($ExpectedProfileSha256.ToLowerInvariant() -eq $profileFileHash) { "pass" } else { "fail" }) -Expected $ExpectedProfileSha256.ToLowerInvariant() -Actual $profileFileHash
    }
}

if ($manifestPath) {
    $manifestExists = Test-Path -LiteralPath $manifestPath -PathType Leaf
    Add-Check -Name "manifest.exists" -Status $(if ($manifestExists) { "pass" } else { "fail" }) -Expected $true -Actual $manifestExists
    if ($manifestExists) {
        $manifestFileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
        if ($ExpectedManifestSha256) {
            $manifestHashValid = $ExpectedManifestSha256 -match '^[0-9a-fA-F]{64}$'
            Add-Check -Name "external.manifest-sha256.format" -Status $(if ($manifestHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedManifestSha256
            if ($manifestHashValid) {
                Add-Check -Name "external.manifest-sha256" -Status $(if ($manifestFileHash -eq $ExpectedManifestSha256.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $ExpectedManifestSha256.ToLowerInvariant() -Actual $manifestFileHash
            }
        }
        try {
            $manifestObject = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            $manifestSchemaValid = $manifestObject.schema -eq "go-obf-release-manifest/v1" -and [int]$manifestObject.version -eq 1
            Add-Check -Name "manifest.schema" -Status $(if ($manifestSchemaValid) { "pass" } else { "fail" }) -Expected "go-obf-release-manifest/v1" -Actual $manifestObject.schema
        } catch {
            Add-Check -Name "manifest.json" -Status "fail" -Expected "valid JSON" -Actual "invalid" -Detail $_.Exception.Message
        }
    }
} elseif ($ExpectedManifestSha256) {
    Add-Check -Name "manifest.required" -Status "fail" -Expected "manifest path" -Actual "missing"
}

try {
    $profileObject = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
} catch {
    Add-Check -Name "profile.json" -Status "fail" -Expected "valid JSON" -Actual "invalid" -Detail $_.Exception.Message
    Emit-Result -ExitCode 2
}

$profileVersion = 0
$profileVersionValid = $false
try {
    if ($null -ne $profileObject.version) {
        $profileVersion = [int]$profileObject.version
        $profileVersionValid = $profileVersion -eq 1 -or $profileVersion -eq 2
    }
} catch {
    $profileVersionValid = $false
}
$schemaValid = $null -ne $profileObject -and (($profileObject.schema -eq "go-obf-profile/v1" -and $profileVersion -eq 1) -or ($profileObject.schema -eq "go-obf-profile/v2" -and $profileVersion -eq 2))
Add-Check -Name "profile.schema" -Status $(if ($schemaValid) { "pass" } else { "fail" }) -Expected "go-obf-profile/v1 or v2" -Actual $(if ($null -eq $profileObject) { $null } else { $profileObject.schema })
if (-not $schemaValid) {
    Emit-Result -ExitCode 2
}

$artifactExists = Test-Path -LiteralPath $artifactPath -PathType Leaf
Add-Check -Name "artifact.exists" -Status $(if ($artifactExists) { "pass" } else { "fail" }) -Expected $true -Actual $artifactExists
if (-not $artifactExists) {
    Emit-Result -ExitCode 2
}

$artifactBytes = [System.IO.File]::ReadAllBytes($artifactPath)
$artifactItem = Get-Item -LiteralPath $artifactPath
$artifactHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
$profileArtifact = $profileObject.artifact

if ($ExpectedSha256) {
    $expectedHashValid = $ExpectedSha256 -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "external.sha256.format" -Status $(if ($expectedHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedSha256
    if ($expectedHashValid) {
        Add-Check -Name "external.sha256" -Status $(if ($ExpectedSha256.ToLowerInvariant() -eq $artifactHash) { "pass" } else { "fail" }) -Expected $ExpectedSha256.ToLowerInvariant() -Actual $artifactHash
    }
}

$profilePathMatches = $false
if ($null -ne $profileArtifact -and $profileArtifact.path) {
    try {
        $profileArtifactPath = Resolve-UserPath -Value ([string]$profileArtifact.path)
        $profilePathMatches = [StringComparer]::OrdinalIgnoreCase.Equals($profileArtifactPath, $artifactPath)
    } catch {
        $profilePathMatches = $false
    }
}
Add-Check -Name "artifact.path" -Status $(if ($profilePathMatches) { "pass" } else { "fail" }) -Expected $artifactPath -Actual $(if ($null -eq $profileArtifact) { $null } else { $profileArtifact.path })

$profileSize = $null
$profileSizeValid = $false
try {
    if ($null -ne $profileArtifact.size) {
        $profileSize = [int64]$profileArtifact.size
        $profileSizeValid = $true
    }
} catch {
    $profileSizeValid = $false
}
$sizeMatches = $profileSizeValid -and $profileSize -eq [int64]$artifactItem.Length
Add-Check -Name "artifact.size" -Status $(if ($sizeMatches) { "pass" } else { "fail" }) -Expected $profileSize -Actual ([int64]$artifactItem.Length)

$hashMatches = $null -ne $profileArtifact -and ([string]$profileArtifact.sha256).ToLowerInvariant() -eq $artifactHash
Add-Check -Name "artifact.sha256" -Status $(if ($hashMatches) { "pass" } else { "fail" }) -Expected $(if ($null -eq $profileArtifact) { $null } else { $profileArtifact.sha256 }) -Actual $artifactHash

$profileCHeader = if ($null -eq $profileObject.auxiliary) { $null } else { $profileObject.auxiliary.cHeader }
$verifiedCHeaderPath = ""
$verifiedCHeaderSize = $null
$verifiedCHeaderHash = ""
if ($RequireCHeader -or $null -ne $profileCHeader) {
    if ($null -eq $profileCHeader) {
        Add-Check -Name "c-header.profile" -Status "fail" -Expected "recorded C header" -Actual "missing"
    } else {
        $headerPathText = [string]$profileCHeader.path
        $headerPathValid = $false
        if ($headerPathText) {
            try {
                $verifiedCHeaderPath = Resolve-UserPath -Value $headerPathText
                $headerPathValid = $true
            } catch {
                $headerPathValid = $false
            }
        }
        Add-Check -Name "c-header.path" -Status $(if ($headerPathValid) { "pass" } else { "fail" }) -Expected "file path" -Actual $headerPathText
        if ($headerPathValid) {
            $headerExists = Test-Path -LiteralPath $verifiedCHeaderPath -PathType Leaf
            Add-Check -Name "c-header.exists" -Status $(if ($headerExists) { "pass" } else { "fail" }) -Expected $true -Actual $headerExists
            if ($headerExists) {
                $headerItem = Get-Item -LiteralPath $verifiedCHeaderPath
                $headerProfileSize = $null
                $headerProfileSizeValid = $false
                try {
                    if ($null -ne $profileCHeader.size) {
                        $headerProfileSize = [int64]$profileCHeader.size
                        $headerProfileSizeValid = $true
                    }
                } catch {
                    $headerProfileSizeValid = $false
                }
                $verifiedCHeaderSize = [int64]$headerItem.Length
                Add-Check -Name "c-header.size" -Status $(if ($headerProfileSizeValid -and $headerProfileSize -eq $verifiedCHeaderSize) { "pass" } else { "fail" }) -Expected $headerProfileSize -Actual $verifiedCHeaderSize
                $verifiedCHeaderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $verifiedCHeaderPath).Hash.ToLowerInvariant()
                $headerProfileHash = [string]$profileCHeader.sha256
                Add-Check -Name "c-header.sha256" -Status $(if ($headerProfileHash -match '^[0-9a-fA-F]{64}$' -and $headerProfileHash.ToLowerInvariant() -eq $verifiedCHeaderHash) { "pass" } else { "fail" }) -Expected $headerProfileHash -Actual $verifiedCHeaderHash
            }
        }
    }
}

$compilerProfile = $profileObject.compiler
$compilerPathToCheck = $CompilerPath
if (-not $compilerPathToCheck -and $compilerProfile -and $compilerProfile.path) {
    $compilerPathToCheck = [string]$compilerProfile.path
}
if ($RequireCompilerBinary -and -not $compilerPathToCheck) {
    Add-Check -Name "compiler.binary.path" -Status "fail" -Expected "compiler path" -Actual "missing"
}
if ($null -ne $compilerProfile -and $compilerProfile.sha256) {
    $profileCompilerHash = [string]$compilerProfile.sha256
    $profileCompilerHashValid = $profileCompilerHash -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "compiler.sha256.format" -Status $(if ($profileCompilerHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $profileCompilerHash
    if ($profileCompilerHashValid -and $compilerPathToCheck) {
        try {
            $resolvedCompilerPath = Resolve-UserPath -Value ([string]$compilerPathToCheck)
            if (Test-Path -LiteralPath $resolvedCompilerPath -PathType Leaf) {
                $actualCompilerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedCompilerPath).Hash.ToLowerInvariant()
                Add-Check -Name "compiler.binary-sha256" -Status $(if ($actualCompilerHash -eq $profileCompilerHash.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $profileCompilerHash.ToLowerInvariant() -Actual $actualCompilerHash
            } else {
                Add-Check -Name "compiler.binary-sha256" -Status $(if ($RequireCompilerBinary) { "fail" } else { "skip" }) -Expected $profileCompilerHash.ToLowerInvariant() -Actual "missing" -Detail "compiler path is not available on this machine"
            }
        } catch {
            Add-Check -Name "compiler.binary-sha256" -Status "fail" -Expected $profileCompilerHash.ToLowerInvariant() -Actual "error" -Detail $_.Exception.Message
        }
    }
}
if ($ExpectedCompilerSha256) {
    $compilerHash = if ($actualCompilerHash) { $actualCompilerHash } elseif ($null -eq $compilerProfile) { "" } else { [string]$compilerProfile.sha256 }
    $expectedCompilerHashValid = $ExpectedCompilerSha256 -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "external.compiler.sha256.format" -Status $(if ($expectedCompilerHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedCompilerSha256
    if ($expectedCompilerHashValid) {
        Add-Check -Name "external.compiler.sha256" -Status $(if ($compilerHash -and $compilerHash.ToLowerInvariant() -eq $ExpectedCompilerSha256.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $ExpectedCompilerSha256.ToLowerInvariant() -Actual $compilerHash
    }
}
if ($ExpectedCompilerCommit) {
    $compilerCommit = if ($null -eq $compilerProfile) { "" } else { [string]$compilerProfile.commit }
    $actualCommit = if ($CompilerRoot) { Get-GitRevision -Directory (Resolve-UserPath -Value $CompilerRoot) } else { $compilerCommit }
    $actualCompilerCommit = $actualCommit
    Add-Check -Name "external.compiler.commit" -Status $(if ($actualCommit -and $actualCommit -eq $ExpectedCompilerCommit) { "pass" } else { "fail" }) -Expected $ExpectedCompilerCommit -Actual $actualCommit
}
if ($RequireCleanCompiler) {
    $compilerDirty = if ($null -eq $compilerProfile) { $null } else { $compilerProfile.dirty }
    $actualDirty = if ($CompilerRoot) { Get-GitDirty -Directory (Resolve-UserPath -Value $CompilerRoot) } else { $compilerDirty }
    $actualCompilerDirty = $actualDirty
    Add-Check -Name "external.compiler.clean" -Status $(if ($actualDirty -eq $false) { "pass" } else { "fail" }) -Expected $false -Actual $actualDirty
}
if ($CompilerRoot -or $RequireCompilerSource -or $ExpectedCompilerSourceSha256) {
    $sourceRoot = if ($CompilerRoot) { Resolve-UserPath -Value $CompilerRoot } elseif ($compilerProfile -and $compilerProfile.sourceRoot) { Resolve-UserPath -Value ([string]$compilerProfile.sourceRoot) } else { "" }
    if (-not $sourceRoot) {
        Add-Check -Name "compiler.source.path" -Status "fail" -Expected "compiler source root" -Actual "missing"
    } elseif (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
        Add-Check -Name "compiler.source.path" -Status "fail" -Expected "directory" -Actual $sourceRoot
    } else {
        try {
            $sourceFiles = Get-CompilerSourceFiles -Directory $sourceRoot
            $sourceDigest = Get-TrackedSourceDigest -Directory $sourceRoot -Files $sourceFiles
            $actualCompilerSourceHash = $sourceDigest
            $profileSourceDigest = if ($compilerProfile -and $compilerProfile.source) { [string]$compilerProfile.source.sha256 } else { "" }
            Add-Check -Name "compiler.source-sha256" -Status $(if ($profileSourceDigest -and $sourceDigest -eq $profileSourceDigest.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $profileSourceDigest -Actual $sourceDigest
            if ($ExpectedCompilerSourceSha256) {
                $expectedSourceValid = $ExpectedCompilerSourceSha256 -match '^[0-9a-fA-F]{64}$'
                Add-Check -Name "external.compiler.source-sha256.format" -Status $(if ($expectedSourceValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedCompilerSourceSha256
                if ($expectedSourceValid) {
                    Add-Check -Name "external.compiler.source-sha256" -Status $(if ($sourceDigest -eq $ExpectedCompilerSourceSha256.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $ExpectedCompilerSourceSha256.ToLowerInvariant() -Actual $sourceDigest
                }
            }
        } catch {
            Add-Check -Name "compiler.source-sha256" -Status "fail" -Expected "digest" -Actual "error" -Detail $_.Exception.Message
        }
    }
}
$toolingProfile = $profileObject.tooling
if ($RequireTooling -or $null -ne $toolingProfile) {
    if (-not $CompilerRoot) {
        Add-Check -Name "tooling.root" -Status $(if ($RequireTooling) { "fail" } else { "skip" }) -Expected "CompilerRoot" -Actual "missing"
    } else {
        $toolRoot = Join-Path (Resolve-UserPath -Value $CompilerRoot) "misc\obf"
        foreach ($toolName in @("build", "verify", "matrix", "integrity")) {
            $entry = if ($null -eq $toolingProfile) { $null } else { $toolingProfile.$toolName }
            $fileName = if ($entry -and $entry.fileName) { [string]$entry.fileName } else { "$toolName.ps1" }
            $toolPath = Join-Path $toolRoot $fileName
            if (Test-Path -LiteralPath $toolPath -PathType Leaf) {
                $toolHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $toolPath).Hash.ToLowerInvariant()
                $profileToolHash = if ($entry) { [string]$entry.sha256 } else { "" }
                Add-Check -Name "tooling.$toolName.sha256" -Status $(if ($profileToolHash -and $profileToolHash -eq $toolHash) { "pass" } else { "fail" }) -Expected $profileToolHash -Actual $toolHash
            } else {
                Add-Check -Name "tooling.$toolName.sha256" -Status $(if ($RequireTooling) { "fail" } else { "skip" }) -Expected "file" -Actual "missing"
            }
        }
    }
}

$buildProfile = $profileObject.build
$seedProfile = if ($null -eq $buildProfile) { $null } else { $buildProfile.seed }
$profileSeedFingerprint = if ($null -eq $seedProfile) { "" } else { [string]$seedProfile.fingerprint }
if ($profileSeedFingerprint) {
    Add-Check -Name "seed-fingerprint.format" -Status $(if ($profileSeedFingerprint -match '^[0-9a-fA-F]{64}$') { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $profileSeedFingerprint
}
if ($ExpectedSeedFingerprint) {
    $seedFingerprintValid = $ExpectedSeedFingerprint -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "external.seed-fingerprint.format" -Status $(if ($seedFingerprintValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedSeedFingerprint
    if ($seedFingerprintValid) {
        Add-Check -Name "external.seed-fingerprint" -Status $(if ($profileSeedFingerprint.ToLowerInvariant() -eq $ExpectedSeedFingerprint.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $ExpectedSeedFingerprint.ToLowerInvariant() -Actual $profileSeedFingerprint
    }
}

$protection = $profileObject.protection
$markers = $profileObject.markers
$reportFunctions = @()
if ($null -ne $profileObject.obfReport) {
    $reportFunctions = @($profileObject.obfReport.functions)
    $recordedReportCount = -1
    try {
        $recordedReportCount = [int]$profileObject.obfReport.count
    } catch {
        $recordedReportCount = -1
    }
    Add-Check -Name "coverage.report-count" -Status $(if ($recordedReportCount -eq $reportFunctions.Count) { "pass" } else { "fail" }) -Expected $recordedReportCount -Actual $reportFunctions.Count
}
$reportFunctionNames = @($reportFunctions | ForEach-Object { [string]$_.name })
if ($MinReportFunctions -ge 0) {
    Add-Check -Name "coverage.minimum-functions" -Status $(if ($reportFunctions.Count -ge $MinReportFunctions) { "pass" } else { "fail" }) -Expected ">=$MinReportFunctions" -Actual $reportFunctions.Count
}
if ($MinV4Aliases -ge 0) {
    $aliasReports = @($reportFunctions | Where-Object { ([string]$_.applied) -match 'aliases=([0-9]+)' })
    $aliasValues = @($aliasReports | ForEach-Object {
        $m = [regex]::Match([string]$_.applied, 'aliases=([0-9]+)')
        if ($m.Success) { [int]$m.Groups[1].Value }
    })
    $aliasMinimum = if ($aliasValues.Count -eq 0) { 0 } else { ($aliasValues | Measure-Object -Minimum).Minimum }
    Add-Check -Name "coverage.minimum-v4-aliases" -Status $(if ($aliasMinimum -ge $MinV4Aliases) { "pass" } else { "fail" }) -Expected ">=$MinV4Aliases" -Actual $aliasMinimum
}
if ($RequireNativeCFG -or $RequireNativeCFGFull) {
    $nativeCFGReports = @($reportFunctions | Where-Object {
        ([string]$_.applied) -match '(^|\s)obf=cfg-opaque-dispatch-v2(\s|$)'
    })
    Add-Check -Name "coverage.native-cfg-v2" -Status $(if ($nativeCFGReports.Count -gt 0) { "pass" } else { "fail" }) -Expected ">=1 protected function" -Actual $nativeCFGReports.Count
    if ($RequireNativeCFGFull) {
        $nativeFullReports = @($nativeCFGReports | Where-Object {
            ([string]$_.applied) -match '(^|\s)coverage=full(\s|$)'
        })
        $nativeFullOK = $nativeCFGReports.Count -gt 0 -and $nativeFullReports.Count -eq $nativeCFGReports.Count
        Add-Check -Name "coverage.native-cfg-v2.full" -Status $(if ($nativeFullOK) { "pass" } else { "fail" }) -Expected "all native CFG v2 reports" -Actual "$($nativeFullReports.Count)/$($nativeCFGReports.Count)"
    }
}
foreach ($requiredFunction in @($RequireFunction | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })) {
    $requiredName = [string]$requiredFunction
    $requiredPresent = $reportFunctionNames -contains $requiredName
    Add-Check -Name ("coverage.function/" + (Get-Sha256Text -Value $requiredName).Substring(0, 16)) -Status $(if ($requiredPresent) { "pass" } else { "fail" }) -Expected "reported" -Actual $(if ($requiredPresent) { "reported" } else { "missing" })
}
$protectedFunctions = @($reportFunctions | Where-Object {
    $_.name -and ([string]$_.requested -notmatch '(^|,)noprotect(,|$)')
})
$hashedFunctions = @($protectedFunctions | Where-Object {
    ([string]$_.applied) -match '(^|\s)name=hash-v1(\s|$)'
})

$runtimeCheckMode = if ($null -eq $protection) { "" } else { [string]$protection.runtimeChecks }
if ($RequireRuntimeChecks -or $RequireRuntimeGuardV3) {
    $runtimeVersion = if ($runtimeCheckMode -eq "entry-v3") { "v3" } elseif ($runtimeCheckMode -eq "entry-v2") { "v2" } else { "" }
    $runtimeModeExpected = if ($RequireRuntimeGuardV3) { "entry-v3" } else { "entry-v3 or entry-v2" }
    $runtimeModeOK = if ($RequireRuntimeGuardV3) { $runtimeVersion -eq "v3" } else { [bool]$runtimeVersion }
    Add-Check -Name "runtime-checks.profile" -Status $(if ($runtimeModeOK) { "pass" } else { "fail" }) -Expected $runtimeModeExpected -Actual $runtimeCheckMode
    $guardedFunctions = @($protectedFunctions | Where-Object {
        ([string]$_.applied) -match ("(^|\s)runtime=entry-" + $runtimeVersion + "(\s|$)")
    })
    $runtimeCoverageOK = $protectedFunctions.Count -gt 0 -and $guardedFunctions.Count -eq $protectedFunctions.Count
    Add-Check -Name "runtime-checks.coverage" -Status $(if ($runtimeCoverageOK) { "pass" } else { "fail" }) -Expected "all protected functions" -Actual "$($guardedFunctions.Count)/$($protectedFunctions.Count)"

    if ($runtimeVersion -eq "v3") {
        $guardV3Marker = if ($null -eq $markers) { $null } else { $markers.runtimeGuardV3 }
        $guardV3Enabled = $null -ne $guardV3Marker -and [bool]$guardV3Marker.enabled
        Add-Check -Name "runtime-checks.v3.profile" -Status $(if ($guardV3Enabled) { "pass" } else { "fail" }) -Expected "enabled image and platform bindings" -Actual $(if ($guardV3Enabled) { [string]$guardV3Marker.target } else { "missing" })
        foreach ($markerName in @("sealLo", "sealHi", "bootstrap", "platform")) {
            $wordMarker = if ($guardV3Enabled) { $guardV3Marker.$markerName } else { $null }
            $wordHex = if ($null -ne $wordMarker) { [string]$wordMarker.littleEndian } else { "" }
            $wordBytes = Convert-HexToBytes -Value $wordHex
            $wordFormatOK = $null -ne $wordBytes -and $wordBytes.Length -eq 8
            Add-Check -Name "runtime-checks.v3.$markerName.profile" -Status $(if ($wordFormatOK) { "pass" } else { "fail" }) -Expected "64-bit marker" -Actual $(if ($wordFormatOK) { $wordHex } else { "missing" })
            if ($wordFormatOK) {
                $imageCount = Find-ByteSequenceCount -Data $artifactBytes -Needle $wordBytes
                $recordedCount = -1
                try {
                    $recordedCount = [int]$wordMarker.count
                } catch {
                    $recordedCount = -1
                }
                $wordOK = $imageCount -gt 0 -and $recordedCount -eq $imageCount
                Add-Check -Name "runtime-checks.v3.$markerName.marker" -Status $(if ($wordOK) { "pass" } else { "fail" }) -Expected "recorded non-zero count" -Actual "$imageCount/$recordedCount"
            }
        }
    } else {
        $guardV2Marker = if ($null -eq $markers) { $null } else { $markers.runtimeGuardV2 }
        $guardV2Enabled = $null -ne $guardV2Marker -and [bool]$guardV2Marker.enabled
        $guardV2Hex = if ($guardV2Enabled) { [string]$guardV2Marker.littleEndian } else { "" }
        $guardV2Bytes = Convert-HexToBytes -Value $guardV2Hex
        $guardV2FormatOK = $guardV2Enabled -and $null -ne $guardV2Bytes -and $guardV2Bytes.Length -eq 8
        Add-Check -Name "runtime-checks.bootstrap-profile" -Status $(if ($guardV2FormatOK) { "pass" } else { "fail" }) -Expected "enabled 64-bit bootstrap seal" -Actual $(if ($guardV2Enabled) { $guardV2Hex } else { "missing" })
        if ($guardV2FormatOK) {
            $guardV2Count = Find-ByteSequenceCount -Data $artifactBytes -Needle $guardV2Bytes
            $recordedGuardV2Count = -1
            try {
                $recordedGuardV2Count = [int]$guardV2Marker.count
            } catch {
                $recordedGuardV2Count = -1
            }
            $guardV2MarkerOK = $guardV2Count -gt 0 -and $recordedGuardV2Count -eq $guardV2Count
            Add-Check -Name "runtime-checks.bootstrap-marker" -Status $(if ($guardV2MarkerOK) { "pass" } else { "fail" }) -Expected "recorded non-zero count" -Actual "$guardV2Count/$recordedGuardV2Count"
        }
    }
}

if ($RequireStringV4) {
    $stringRuntime = if ($null -eq $protection) { "" } else { [string]$protection.stringRuntime }
    Add-Check -Name "string-v4.profile" -Status $(if ($stringRuntime -match '(^|\+)v4-stream($|\+)') { "pass" } else { "fail" }) -Expected "v4-stream" -Actual $stringRuntime
    $streamFunctions = @($protectedFunctions | Where-Object {
        ([string]$_.applied) -match '(^|\s)encrypt=str-runtime-v4-stream(\s|$)'
    })
    Add-Check -Name "string-v4.coverage" -Status $(if ($streamFunctions.Count -gt 0) { "pass" } else { "fail" }) -Expected ">=1 protected function" -Actual $streamFunctions.Count
}

if ($RequireStringV5) {
    $stringRuntime = if ($null -eq $protection) { "" } else { [string]$protection.stringRuntime }
    Add-Check -Name "string-v5.profile" -Status $(if ($stringRuntime -match '(^|\+)v5-lease($|\+)') { "pass" } else { "fail" }) -Expected "v5-lease" -Actual $stringRuntime
    $leaseStreamFunctions = @($protectedFunctions | Where-Object {
        ([string]$_.applied) -match '(^|\s)encrypt=str-runtime-v5-lease(\s|$)'
    })
    Add-Check -Name "string-v5.coverage" -Status $(if ($leaseStreamFunctions.Count -gt 0) { "pass" } else { "fail" }) -Expected ">=1 protected function" -Actual $leaseStreamFunctions.Count
}

$nameMode = if ($null -eq $protection) { "" } else { [string]$protection.names }
$protectedPrefix = if ($null -ne $markers -and $markers.protectedNamePrefix) { [string]$markers.protectedNamePrefix } else { "obf.fn." }
$protectedPrefixBytes = [System.Text.Encoding]::UTF8.GetBytes($protectedPrefix)
$protectedPrefixCount = Find-ByteSequenceCount -Data $artifactBytes -Needle $protectedPrefixBytes
if ($nameMode -eq "hidden-protected") {
    Add-Check -Name "protected-names.hidden" -Status $(if ($protectedPrefixCount -eq 0) { "pass" } else { "fail" }) -Expected 0 -Actual $protectedPrefixCount
} elseif ($nameMode -eq "hashed-protected") {
    $expectedCount = if ($hashedFunctions.Count -gt 0) { 1 } else { 0 }
    $status = if ($protectedPrefixCount -ge $expectedCount) { "pass" } else { "fail" }
    Add-Check -Name "protected-names.hashed" -Status $status -Expected $(if ($expectedCount -gt 0) { ">=1" } else { 0 }) -Actual $protectedPrefixCount
} elseif ($nameMode -eq "stable") {
    Add-Check -Name "protected-names.stable" -Status $(if ($protectedPrefixCount -eq 0) { "pass" } else { "fail" }) -Expected 0 -Actual $protectedPrefixCount
} else {
    Add-Check -Name "protected-names.mode" -Status "skip" -Expected "known mode" -Actual $nameMode -Detail "profile has no recognized name mode"
}

foreach ($function in $protectedFunctions) {
    $functionName = [string]$function.name
    $functionBytes = [System.Text.Encoding]::UTF8.GetBytes($functionName)
    $functionOffset = Find-ByteSequence -Data $artifactBytes -Needle $functionBytes
    $isHashedFunction = ([string]$function.applied) -match '(^|\s)name=hash-v1(\s|$)'
    if ($nameMode -eq "stable") {
        Add-Check -Name ("function-name.present/" + (Get-Sha256Text -Value $functionName).Substring(0, 16)) -Status $(if ($functionOffset -ge 0) { "pass" } else { "fail" }) -Expected "present" -Actual $functionOffset
    } elseif (-not $isHashedFunction) {
        Add-Check -Name ("function-name.compat/" + (Get-Sha256Text -Value $functionName).Substring(0, 16)) -Status "skip" -Expected "stable export" -Actual $functionOffset -Detail "function did not receive name=hash-v1"
    } else {
        Add-Check -Name ("function-name.absent/" + (Get-Sha256Text -Value $functionName).Substring(0, 16)) -Status $(if ($functionOffset -lt 0) { "pass" } else { "fail" }) -Expected "absent" -Actual $functionOffset
    }
}

$sourceMode = if ($null -eq $protection) { "" } else { [string]$protection.fileNames }
$sourcePrefix = if ($null -ne $markers -and $markers.sourcePrefix) { [string]$markers.sourcePrefix } else { "obf.src." }
$sourceCount = Find-ByteSequenceCount -Data $artifactBytes -Needle ([System.Text.Encoding]::UTF8.GetBytes($sourcePrefix))
if ($sourceMode -eq "hashed-pclntab") {
    $expectedSourceCount = if ($null -ne $markers -and $markers.sourceNameCount -gt 0) { 1 } else { 0 }
    Add-Check -Name "source-names.hashed" -Status $(if ($sourceCount -ge $expectedSourceCount) { "pass" } else { "fail" }) -Expected $(if ($expectedSourceCount -gt 0) { ">=1" } else { 0 }) -Actual $sourceCount
} elseif ($sourceMode -eq "original") {
    Add-Check -Name "source-names.original" -Status "skip" -Expected "original paths may be present" -Actual $sourceCount -Detail "verification does not require a particular source path"
}

$magicProfile = if ($null -eq $markers) { $null } else { $markers.pclntabMagic }
if ($null -ne $magicProfile -and $magicProfile.littleEndian) {
    $magicBytes = Convert-HexToBytes -Value ([string]$magicProfile.littleEndian)
    if ($null -eq $magicBytes) {
        Add-Check -Name "pclntab.magic" -Status "fail" -Expected "hex marker" -Actual $magicProfile.littleEndian -Detail "profile marker is not valid hexadecimal"
    } else {
        $magicOffset = Find-ByteSequence -Data $artifactBytes -Needle $magicBytes
    $recordedOffset = -1
    try {
        if ($null -ne $magicProfile.offset) {
            $recordedOffset = [int]$magicProfile.offset
        }
    } catch {
        $recordedOffset = -1
    }
    $offsetMatches = $recordedOffset -lt 0 -or ($recordedOffset -lt $artifactBytes.Length -and $magicOffset -eq $recordedOffset)
    $magicStatus = $magicOffset -ge 0 -and $offsetMatches
        Add-Check -Name "pclntab.magic" -Status $(if ($magicStatus) { "pass" } else { "fail" }) -Expected ([string]$magicProfile.littleEndian) -Actual $(if ($magicOffset -ge 0) { $magicOffset } else { -1 })
    }
} else {
    Add-Check -Name "pclntab.magic" -Status "skip" -Expected "profile marker" -Actual $null -Detail "profile does not contain a magic marker"
}

$entryProfile = if ($null -eq $markers) { $null } else { $markers.entryKey }
if ($null -ne $entryProfile -and [bool]$entryProfile.enabled) {
    $entryBytes = Convert-HexToBytes -Value ([string]$entryProfile.littleEndian)
    if ($null -eq $entryBytes) {
        Add-Check -Name "entry-offset.key" -Status "fail" -Expected "hex marker" -Actual $entryProfile.littleEndian -Detail "profile marker is not valid hexadecimal"
    } else {
        $entryCount = Find-ByteSequenceCount -Data $artifactBytes -Needle $entryBytes
        Add-Check -Name "entry-offset.key" -Status $(if ($entryCount -gt 0) { "pass" } else { "fail" }) -Expected ">=1" -Actual $entryCount
    }
} elseif ($null -ne $entryProfile) {
    Add-Check -Name "entry-offset.key" -Status "skip" -Expected "raw offsets" -Actual "disabled"
} else {
    Add-Check -Name "entry-offset.key" -Status "skip" -Expected "profile marker" -Actual $null -Detail "profile does not contain an entry key marker"
}

$scanValues = @($ForbiddenText) + @($ExpectedAbsent)
$metadataValues = @($ForbiddenMetadata)
$uniqueScanValues = @($scanValues | Where-Object { -not [string]::IsNullOrEmpty([string]$_) } | Select-Object -Unique)
if ($uniqueScanValues.Count -eq 0) {
    $profileScans = @()
    if ($null -ne $profileObject.plaintextScans) {
        $profileScans = @($profileObject.plaintextScans)
    }
    if ($profileScans.Count -gt 0) {
        Add-Check -Name "plaintext-scans.inputs" -Status "skip" -Expected "values supplied to verifier" -Actual 0 -Detail "profile stores digests only; pass -ExpectedAbsent or -ForbiddenText to rescan"
    }
} else {
    foreach ($literal in $uniqueScanValues) {
        $literalString = [string]$literal
        $literalBytes = [System.Text.Encoding]::UTF8.GetBytes($literalString)
        $offset = Find-ByteSequence -Data $artifactBytes -Needle $literalBytes
        Add-Check -Name ("plaintext.absent/" + (Get-Sha256Text -Value $literalString).Substring(0, 16)) -Status $(if ($offset -lt 0) { "pass" } else { "fail" }) -Expected "absent" -Actual $offset
    }
}
foreach ($metadataLiteral in @($metadataValues | Where-Object { -not [string]::IsNullOrEmpty([string]$_) } | Select-Object -Unique)) {
    $metadataString = [string]$metadataLiteral
    $metadataBytes = [System.Text.Encoding]::UTF8.GetBytes($metadataString)
    $metadataOffset = Find-ByteSequence -Data $artifactBytes -Needle $metadataBytes
    Add-Check -Name ("metadata.absent/" + (Get-Sha256Text -Value $metadataString).Substring(0, 16)) -Status $(if ($metadataOffset -lt 0) { "pass" } else { "fail" }) -Expected "absent" -Actual $metadataOffset
}

if ($null -ne $manifestObject) {
    Add-Check -Name "manifest.artifact.sha256" -Status $(if ([string]$manifestObject.artifact.sha256 -eq $artifactHash) { "pass" } else { "fail" }) -Expected $artifactHash -Actual $manifestObject.artifact.sha256
    Add-Check -Name "manifest.artifact.size" -Status $(if ([int64]$manifestObject.artifact.size -eq [int64]$artifactItem.Length) { "pass" } else { "fail" }) -Expected ([int64]$artifactItem.Length) -Actual $manifestObject.artifact.size
    Add-Check -Name "manifest.profile.sha256" -Status $(if ([string]$manifestObject.profile.sha256 -eq $profileFileHash) { "pass" } else { "fail" }) -Expected $profileFileHash -Actual $manifestObject.profile.sha256
    $manifestCHeader = if ($null -eq $manifestObject.auxiliary) { $null } else { $manifestObject.auxiliary.cHeader }
    if ($RequireCHeader -or $null -ne $profileCHeader -or $null -ne $manifestCHeader) {
        $manifestHeaderPresent = $null -ne $manifestCHeader
        Add-Check -Name "manifest.c-header.record" -Status $(if ($manifestHeaderPresent -and $null -ne $profileCHeader) { "pass" } else { "fail" }) -Expected "profile-bound C header" -Actual $(if ($manifestHeaderPresent) { "present" } else { "missing" })
        if ($manifestHeaderPresent -and $null -ne $profileCHeader) {
            Add-Check -Name "manifest.c-header.filename" -Status $(if ([string]$manifestCHeader.fileName -eq [System.IO.Path]::GetFileName([string]$profileCHeader.path)) { "pass" } else { "fail" }) -Expected ([System.IO.Path]::GetFileName([string]$profileCHeader.path)) -Actual $manifestCHeader.fileName
            Add-Check -Name "manifest.c-header.size" -Status $(if ([int64]$manifestCHeader.size -eq [int64]$profileCHeader.size) { "pass" } else { "fail" }) -Expected $profileCHeader.size -Actual $manifestCHeader.size
            Add-Check -Name "manifest.c-header.sha256" -Status $(if ([string]$manifestCHeader.sha256 -eq [string]$profileCHeader.sha256) { "pass" } else { "fail" }) -Expected $profileCHeader.sha256 -Actual $manifestCHeader.sha256
        }
    }
    $manifestCompilerHash = [string]$manifestObject.compiler.sha256
    $compilerHashForManifest = if ($actualCompilerHash) { $actualCompilerHash } elseif ($compilerProfile) { [string]$compilerProfile.sha256 } else { "" }
    Add-Check -Name "manifest.compiler.sha256" -Status $(if ($manifestCompilerHash -and $manifestCompilerHash -eq $compilerHashForManifest) { "pass" } else { "fail" }) -Expected $compilerHashForManifest -Actual $manifestCompilerHash
    $sourceHashForManifest = if ($actualCompilerSourceHash) { $actualCompilerSourceHash } elseif ($compilerProfile -and $compilerProfile.source) { [string]$compilerProfile.source.sha256 } else { "" }
    Add-Check -Name "manifest.compiler.source-sha256" -Status $(if ([string]$manifestObject.compiler.sourceSha256 -eq $sourceHashForManifest) { "pass" } else { "fail" }) -Expected $sourceHashForManifest -Actual $manifestObject.compiler.sourceSha256
    $commitForManifest = if ($actualCompilerCommit) { $actualCompilerCommit } elseif ($compilerProfile) { [string]$compilerProfile.commit } else { "" }
    Add-Check -Name "manifest.compiler.commit" -Status $(if ([string]$manifestObject.compiler.commit -eq $commitForManifest) { "pass" } else { "fail" }) -Expected $commitForManifest -Actual $manifestObject.compiler.commit
    if ($toolingProfile) {
        Add-Check -Name "manifest.tooling.build" -Status $(if ([string]$manifestObject.tooling.buildSha256 -eq [string]$toolingProfile.build.sha256) { "pass" } else { "fail" }) -Expected $toolingProfile.build.sha256 -Actual $manifestObject.tooling.buildSha256
        Add-Check -Name "manifest.tooling.verify" -Status $(if ([string]$manifestObject.tooling.verifySha256 -eq [string]$toolingProfile.verify.sha256) { "pass" } else { "fail" }) -Expected $toolingProfile.verify.sha256 -Actual $manifestObject.tooling.verifySha256
        Add-Check -Name "manifest.tooling.matrix" -Status $(if ([string]$manifestObject.tooling.matrixSha256 -eq [string]$toolingProfile.matrix.sha256) { "pass" } else { "fail" }) -Expected $toolingProfile.matrix.sha256 -Actual $manifestObject.tooling.matrixSha256
        Add-Check -Name "manifest.tooling.integrity" -Status $(if ([string]$manifestObject.tooling.integritySha256 -eq [string]$toolingProfile.integrity.sha256) { "pass" } else { "fail" }) -Expected $toolingProfile.integrity.sha256 -Actual $manifestObject.tooling.integritySha256
    }
    Add-Check -Name "manifest.seed-fingerprint" -Status $(if ([string]$manifestObject.build.seedFingerprint -eq $profileSeedFingerprint) { "pass" } else { "fail" }) -Expected $profileSeedFingerprint -Actual $manifestObject.build.seedFingerprint
    if ($buildProfile -and $buildProfile.target) {
        Add-Check -Name "manifest.target.goos" -Status $(if ([string]$manifestObject.build.GOOS -eq [string]$buildProfile.target.GOOS) { "pass" } else { "fail" }) -Expected $buildProfile.target.GOOS -Actual $manifestObject.build.GOOS
        Add-Check -Name "manifest.target.goarch" -Status $(if ([string]$manifestObject.build.GOARCH -eq [string]$buildProfile.target.GOARCH) { "pass" } else { "fail" }) -Expected $buildProfile.target.GOARCH -Actual $manifestObject.build.GOARCH
        Add-Check -Name "manifest.target.cgo" -Status $(if ([string]$manifestObject.build.CGO_ENABLED -eq [string]$buildProfile.target.CGO_ENABLED) { "pass" } else { "fail" }) -Expected $buildProfile.target.CGO_ENABLED -Actual $manifestObject.build.CGO_ENABLED
    }
    if ($buildProfile -and $null -ne $buildProfile.mode) {
        Add-Check -Name "manifest.build.mode" -Status $(if ([string]$manifestObject.build.mode -eq [string]$buildProfile.mode) { "pass" } else { "fail" }) -Expected $buildProfile.mode -Actual $manifestObject.build.mode
    }
    if ($manifestObject.protection) {
        Add-Check -Name "manifest.protection.runtime-checks" -Status $(if ([string]$manifestObject.protection.runtimeChecks -eq $runtimeCheckMode) { "pass" } else { "fail" }) -Expected $runtimeCheckMode -Actual $manifestObject.protection.runtimeChecks
    }
}

Emit-Result -ExitCode $(if ($failures.Count -eq 0) { 0 } else { 1 })
