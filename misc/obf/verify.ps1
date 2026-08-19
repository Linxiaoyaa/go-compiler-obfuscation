param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$Profile,

    [string]$ExpectedSha256 = "",
    [string]$ExpectedProfileSha256 = "",
    [string]$ExpectedSeedFingerprint = "",
    [string]$ExpectedCompilerSha256 = "",
    [string]$ExpectedCompilerCommit = "",
    [switch]$RequireCleanCompiler,
    [string[]]$RequireFunction = @(),
    [int]$MinReportFunctions = -1,
    [string[]]$ForbiddenText = @(),
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
$profileObject = $null
$profileFileHash = $null
$artifactBytes = $null

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
        $profileVersionValid = $profileVersion -eq 1
    }
} catch {
    $profileVersionValid = $false
}
$schemaValid = $null -ne $profileObject -and $profileObject.schema -eq "go-obf-profile/v1" -and $profileVersionValid
Add-Check -Name "profile.schema" -Status $(if ($schemaValid) { "pass" } else { "fail" }) -Expected "go-obf-profile/v1" -Actual $(if ($null -eq $profileObject) { $null } else { $profileObject.schema })
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

$compilerProfile = $profileObject.compiler
if ($null -ne $compilerProfile -and $compilerProfile.sha256) {
    $profileCompilerHash = [string]$compilerProfile.sha256
    $profileCompilerHashValid = $profileCompilerHash -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "compiler.sha256.format" -Status $(if ($profileCompilerHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $profileCompilerHash
    if ($profileCompilerHashValid -and $compilerProfile.path) {
        try {
            $compilerPath = Resolve-UserPath -Value ([string]$compilerProfile.path)
            if (Test-Path -LiteralPath $compilerPath -PathType Leaf) {
                $actualCompilerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $compilerPath).Hash.ToLowerInvariant()
                Add-Check -Name "compiler.binary-sha256" -Status $(if ($actualCompilerHash -eq $profileCompilerHash.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $profileCompilerHash.ToLowerInvariant() -Actual $actualCompilerHash
            } else {
                Add-Check -Name "compiler.binary-sha256" -Status "skip" -Expected $profileCompilerHash.ToLowerInvariant() -Actual "missing" -Detail "profile compiler path is not available on this machine"
            }
        } catch {
            Add-Check -Name "compiler.binary-sha256" -Status "fail" -Expected $profileCompilerHash.ToLowerInvariant() -Actual "error" -Detail $_.Exception.Message
        }
    }
}
if ($ExpectedCompilerSha256) {
    $compilerHash = if ($null -eq $compilerProfile) { "" } else { [string]$compilerProfile.sha256 }
    $expectedCompilerHashValid = $ExpectedCompilerSha256 -match '^[0-9a-fA-F]{64}$'
    Add-Check -Name "external.compiler.sha256.format" -Status $(if ($expectedCompilerHashValid) { "pass" } else { "fail" }) -Expected "64 hex characters" -Actual $ExpectedCompilerSha256
    if ($expectedCompilerHashValid) {
        Add-Check -Name "external.compiler.sha256" -Status $(if ($compilerHash -and $compilerHash.ToLowerInvariant() -eq $ExpectedCompilerSha256.ToLowerInvariant()) { "pass" } else { "fail" }) -Expected $ExpectedCompilerSha256.ToLowerInvariant() -Actual $compilerHash
    }
}
if ($ExpectedCompilerCommit) {
    $compilerCommit = if ($null -eq $compilerProfile) { "" } else { [string]$compilerProfile.commit }
    Add-Check -Name "external.compiler.commit" -Status $(if ($compilerCommit -and $compilerCommit -eq $ExpectedCompilerCommit) { "pass" } else { "fail" }) -Expected $ExpectedCompilerCommit -Actual $compilerCommit
}
if ($RequireCleanCompiler) {
    $compilerDirty = if ($null -eq $compilerProfile) { $null } else { $compilerProfile.dirty }
    Add-Check -Name "external.compiler.clean" -Status $(if ($compilerDirty -eq $false) { "pass" } else { "fail" }) -Expected $false -Actual $compilerDirty
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

Emit-Result -ExitCode $(if ($failures.Count -eq 0) { 0 } else { 1 })
