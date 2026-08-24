param(
    [Parameter(Mandatory = $true)]
    [string]$Artifact,

    [Parameter(Mandatory = $true)]
    [string]$Profile,

    [Parameter(Mandatory = $true)]
    [string]$Manifest,

    [Parameter(Mandatory = $true)]
    [string]$CompilerPath,

    [Parameter(Mandatory = $true)]
    [string]$CompilerRoot,

    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

function Resolve-UserPath {
    param([string]$Value)

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path ([string](Get-Location).Path) $Value))
}

function Copy-Fixture {
    param(
        [string]$Directory,
        [string]$SourceArtifact,
        [string]$SourceProfile,
        [string]$SourceManifest
    )

    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $fixture = [ordered]@{
        artifact = Join-Path $Directory "artifact.exe"
        profile = Join-Path $Directory "artifact.profile.json"
        manifest = Join-Path $Directory "artifact.manifest.json"
    }
    Copy-Item -LiteralPath $SourceArtifact -Destination $fixture.artifact -Force
    Copy-Item -LiteralPath $SourceProfile -Destination $fixture.profile -Force
    Copy-Item -LiteralPath $SourceManifest -Destination $fixture.manifest -Force
    $profileObject = Get-Content -LiteralPath $fixture.profile -Raw | ConvertFrom-Json
    $profileObject.artifact.path = [System.IO.Path]::GetFullPath($fixture.artifact)
    Save-Json -Path $fixture.profile -Object $profileObject
    $manifestObject = Get-Content -LiteralPath $fixture.manifest -Raw | ConvertFrom-Json
    $manifestObject.profile.sha256 = Get-FileSha256 -Path $fixture.profile
    $manifestObject.artifact.fileName = [System.IO.Path]::GetFileName($fixture.artifact)
    Save-Json -Path $fixture.manifest -Object $manifestObject
    return $fixture
}

function Get-FileSha256 {
    param([string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Save-Json {
    param(
        [string]$Path,
        [object]$Object
    )

    $json = $Object | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-Verifier {
    param(
        [hashtable]$Fixture,
        [string]$VerifierPath,
        [string]$Root,
        [string]$ToolchainCompiler,
        [string]$ExpectedSeedFingerprint
    )

    $output = @(& $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $VerifierPath `
        -Artifact $Fixture.artifact `
        -Profile $Fixture.profile `
        -Manifest $Fixture.manifest `
        -CompilerPath $ToolchainCompiler `
        -CompilerRoot $Root `
        -RequireCompilerBinary `
        -RequireCompilerSource `
        -RequireTooling `
        -RequireRuntimeChecks `
        -RequireRuntimeGuardV4 `
        -RequireStringV4 `
        -RequireStringV5 `
        -RequireStringV6 `
        -RequireResidualScan `
        -MinReportFunctions 2 `
        -MinV4Aliases 1 `
        -ExpectedSeedFingerprint $ExpectedSeedFingerprint `
        -ExpectedAbsent "v38-cross-platform-ephemeral" `
        -ForbiddenMetadata $Root 2>&1)
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = ($output -join [Environment]::NewLine)
    }
}

function Assert-ExpectedFailure {
    param(
        [string]$Name,
        [hashtable]$Fixture,
        [string]$VerifierPath,
        [string]$Root,
        [string]$ToolchainCompiler,
        [string]$ExpectedSeedFingerprint,
        [string]$ExpectedCheck
    )

    $result = Invoke-Verifier -Fixture $Fixture -VerifierPath $VerifierPath -Root $Root `
        -ToolchainCompiler $ToolchainCompiler -ExpectedSeedFingerprint $ExpectedSeedFingerprint
    if ($result.ExitCode -eq 0) {
        throw "$Name unexpectedly passed verification"
    }
    if ($ExpectedCheck -and $result.Output -notmatch [regex]::Escape($ExpectedCheck)) {
        throw "$Name failed, but did not report $ExpectedCheck"
    }
    Write-Output "negative pass: $Name (exit=$($result.ExitCode), check=$ExpectedCheck)"
}

$sourceArtifact = Resolve-UserPath -Value $Artifact
$sourceProfile = Resolve-UserPath -Value $Profile
$sourceManifest = Resolve-UserPath -Value $Manifest
$verifierPath = Join-Path $PSScriptRoot "verify.ps1"
$rootPath = Resolve-UserPath -Value $CompilerRoot
$compilerPath = Resolve-UserPath -Value $CompilerPath
$PowerShellExecutable = (Get-Command powershell.exe -ErrorAction Stop).Source
foreach ($path in @($sourceArtifact, $sourceProfile, $sourceManifest, $verifierPath, $compilerPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required integrity fixture is missing: $path"
    }
}
if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
    throw "compiler root is missing: $rootPath"
}
$sourceProfileObject = Get-Content -LiteralPath $sourceProfile -Raw | ConvertFrom-Json
$expectedSeedFingerprint = [string]$sourceProfileObject.build.seed.fingerprint
if ($expectedSeedFingerprint -notmatch '^[0-9a-fA-F]{64}$') {
    throw "source profile does not contain a valid seed fingerprint"
}

if (-not $OutDir) {
    $OutDir = Join-Path ([System.IO.Path]::GetDirectoryName($sourceArtifact)) "integrity-negative"
} else {
    $OutDir = Resolve-UserPath -Value $OutDir
}
if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# First establish that the copied, untouched release record is accepted.
$baseline = Copy-Fixture -Directory (Join-Path $OutDir "baseline") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$baselineResult = Invoke-Verifier -Fixture $baseline -VerifierPath $verifierPath -Root $rootPath `
    -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint
if ($baselineResult.ExitCode -ne 0) {
    throw "baseline verification failed: $($baselineResult.Output)"
}
Write-Output "baseline pass"

# An executable byte change must break both the profile binding and the manifest binding.
$artifactCase = Copy-Fixture -Directory (Join-Path $OutDir "artifact-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$artifactBytes = [System.IO.File]::ReadAllBytes($artifactCase.artifact)
if ($artifactBytes.Length -lt 1) { throw "artifact fixture is empty" }
$artifactBytes[$artifactBytes.Length - 1] = $artifactBytes[$artifactBytes.Length - 1] -bxor 1
[System.IO.File]::WriteAllBytes($artifactCase.artifact, $artifactBytes)
Assert-ExpectedFailure -Name "artifact-byte-tamper" -Fixture $artifactCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "artifact.sha256"

# Keep the hash chain internally consistent while appending a known build marker.
# This isolates the residual metadata scan from the ordinary artifact digest checks.
$metadataCase = Copy-Fixture -Directory (Join-Path $OutDir "metadata-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$metadataBytes = [System.Text.Encoding]::Unicode.GetBytes($rootPath)
$metadataArtifactBytes = [System.IO.File]::ReadAllBytes($metadataCase.artifact)
$combinedBytes = New-Object byte[] ($metadataArtifactBytes.Length + $metadataBytes.Length)
[Array]::Copy($metadataArtifactBytes, 0, $combinedBytes, 0, $metadataArtifactBytes.Length)
[Array]::Copy($metadataBytes, 0, $combinedBytes, $metadataArtifactBytes.Length, $metadataBytes.Length)
[System.IO.File]::WriteAllBytes($metadataCase.artifact, $combinedBytes)
$metadataProfile = Get-Content -LiteralPath $metadataCase.profile -Raw | ConvertFrom-Json
$metadataProfile.artifact.size = [int64]$combinedBytes.Length
$metadataProfile.artifact.sha256 = Get-FileSha256 -Path $metadataCase.artifact
Save-Json -Path $metadataCase.profile -Object $metadataProfile
$metadataManifest = Get-Content -LiteralPath $metadataCase.manifest -Raw | ConvertFrom-Json
$metadataManifest.artifact.size = [int64]$combinedBytes.Length
$metadataManifest.artifact.sha256 = Get-FileSha256 -Path $metadataCase.artifact
$metadataManifest.profile.sha256 = Get-FileSha256 -Path $metadataCase.profile
Save-Json -Path $metadataCase.manifest -Object $metadataManifest
Assert-ExpectedFailure -Name "metadata-residual-tamper" -Fixture $metadataCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "metadata.absent/"

# Change only the manifest's artifact digest; the profile and executable stay intact.
$manifestCase = Copy-Fixture -Directory (Join-Path $OutDir "manifest-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$manifestObject = Get-Content -LiteralPath $manifestCase.manifest -Raw | ConvertFrom-Json
$manifestObject.artifact.sha256 = ("0" * 64)
Save-Json -Path $manifestCase.manifest -Object $manifestObject
Assert-ExpectedFailure -Name "manifest-artifact-hash-tamper" -Fixture $manifestCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "manifest.artifact.sha256"

# Change the recorded compiler hash and update the manifest binding so the compiler check is exercised.
$compilerCase = Copy-Fixture -Directory (Join-Path $OutDir "compiler-hash-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$compilerProfile = Get-Content -LiteralPath $compilerCase.profile -Raw | ConvertFrom-Json
$compilerProfile.compiler.sha256 = ("1" * 64)
Save-Json -Path $compilerCase.profile -Object $compilerProfile
$compilerManifest = Get-Content -LiteralPath $compilerCase.manifest -Raw | ConvertFrom-Json
$compilerManifest.profile.sha256 = Get-FileSha256 -Path $compilerCase.profile
$compilerManifest.compiler.sha256 = ("1" * 64)
Save-Json -Path $compilerCase.manifest -Object $compilerManifest
Assert-ExpectedFailure -Name "compiler-hash-tamper" -Fixture $compilerCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "compiler.binary-sha256"

# Change the source digest in both records while leaving the compiler tree untouched.
$sourceCase = Copy-Fixture -Directory (Join-Path $OutDir "source-digest-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$sourceProfileObject = Get-Content -LiteralPath $sourceCase.profile -Raw | ConvertFrom-Json
$sourceProfileObject.compiler.source.sha256 = ("2" * 64)
Save-Json -Path $sourceCase.profile -Object $sourceProfileObject
$sourceManifestObject = Get-Content -LiteralPath $sourceCase.manifest -Raw | ConvertFrom-Json
$sourceManifestObject.profile.sha256 = Get-FileSha256 -Path $sourceCase.profile
$sourceManifestObject.compiler.sourceSha256 = ("2" * 64)
Save-Json -Path $sourceCase.manifest -Object $sourceManifestObject
Assert-ExpectedFailure -Name "compiler-source-digest-tamper" -Fixture $sourceCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "compiler.source-sha256"

# Change the seed identity in both records; this must be caught independently of the artifact hash.
$seedCase = Copy-Fixture -Directory (Join-Path $OutDir "seed-fingerprint-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$seedProfile = Get-Content -LiteralPath $seedCase.profile -Raw | ConvertFrom-Json
$seedProfile.build.seed.fingerprint = ("3" * 64)
Save-Json -Path $seedCase.profile -Object $seedProfile
$seedManifest = Get-Content -LiteralPath $seedCase.manifest -Raw | ConvertFrom-Json
$seedManifest.profile.sha256 = Get-FileSha256 -Path $seedCase.profile
$seedManifest.build.seedFingerprint = ("3" * 64)
Save-Json -Path $seedCase.manifest -Object $seedManifest
Assert-ExpectedFailure -Name "seed-fingerprint-tamper" -Fixture $seedCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "external.seed-fingerprint"

# Change the declared gate mode in both records. The release verifier must not
# accept a self-consistent profile that silently disables runtime checks.
$runtimeCase = Copy-Fixture -Directory (Join-Path $OutDir "runtime-checks-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$runtimeProfile = Get-Content -LiteralPath $runtimeCase.profile -Raw | ConvertFrom-Json
$runtimeProfile.protection.runtimeChecks = "disabled"
Save-Json -Path $runtimeCase.profile -Object $runtimeProfile
$runtimeManifest = Get-Content -LiteralPath $runtimeCase.manifest -Raw | ConvertFrom-Json
$runtimeManifest.profile.sha256 = Get-FileSha256 -Path $runtimeCase.profile
$runtimeManifest.protection.runtimeChecks = "disabled"
Save-Json -Path $runtimeCase.manifest -Object $runtimeManifest
Assert-ExpectedFailure -Name "runtime-check-mode-tamper" -Fixture $runtimeCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "runtime-checks.profile"

# Keep the profile and manifest internally consistent while downgrading only
# the declared version. Release verification must reject v3 even though the
# compatibility runtime-check switch still accepts historical release records.
$runtimeDowngradeCase = Copy-Fixture -Directory (Join-Path $OutDir "runtime-guard-v4-downgrade") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$runtimeDowngradeProfile = Get-Content -LiteralPath $runtimeDowngradeCase.profile -Raw | ConvertFrom-Json
$runtimeDowngradeProfile.protection.runtimeChecks = "entry-v2"
Save-Json -Path $runtimeDowngradeCase.profile -Object $runtimeDowngradeProfile
$runtimeDowngradeManifest = Get-Content -LiteralPath $runtimeDowngradeCase.manifest -Raw | ConvertFrom-Json
$runtimeDowngradeManifest.profile.sha256 = Get-FileSha256 -Path $runtimeDowngradeCase.profile
$runtimeDowngradeManifest.protection.runtimeChecks = "entry-v2"
Save-Json -Path $runtimeDowngradeCase.manifest -Object $runtimeDowngradeManifest
Assert-ExpectedFailure -Name "runtime-guard-v4-downgrade" -Fixture $runtimeDowngradeCase -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "runtime-checks.profile"

# Keep the declared v4 mode but remove the multi-lane image and metadata
# marker. This verifies that a self-consistent release record cannot omit the
# independent Guard v4 image, platform, and pclntab binding.
$guardV4Case = Copy-Fixture -Directory (Join-Path $OutDir "runtime-guard-v4-marker-tamper") `
    -SourceArtifact $sourceArtifact -SourceProfile $sourceProfile -SourceManifest $sourceManifest
$guardV4Profile = Get-Content -LiteralPath $guardV4Case.profile -Raw | ConvertFrom-Json
$guardV4Profile.markers.runtimeGuardV4.enabled = $false
Save-Json -Path $guardV4Case.profile -Object $guardV4Profile
$guardV4Manifest = Get-Content -LiteralPath $guardV4Case.manifest -Raw | ConvertFrom-Json
$guardV4Manifest.profile.sha256 = Get-FileSha256 -Path $guardV4Case.profile
Save-Json -Path $guardV4Case.manifest -Object $guardV4Manifest
Assert-ExpectedFailure -Name "runtime-guard-v4-marker-tamper" -Fixture $guardV4Case -VerifierPath $verifierPath `
    -Root $rootPath -ToolchainCompiler $compilerPath -ExpectedSeedFingerprint $expectedSeedFingerprint `
    -ExpectedCheck "runtime-checks.v4.profile"

Write-Output "integrity negative suite passed"
exit 0
