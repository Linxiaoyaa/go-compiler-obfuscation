param(
    [string[]]$Target = @("windows/amd64", "linux/amd64", "linux/arm64", "linux/riscv64", "darwin/amd64", "darwin/arm64"),
    [string]$OutDir = "",
    [switch]$RequireCleanCompiler
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$fixture = Join-Path $PSScriptRoot "testdata\v38matrix"
$nativeFixture = Join-Path $PSScriptRoot "testdata\nativecfg"
if (-not $OutDir) {
    $OutDir = Join-Path $root "work\v38-cross-platform"
} elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path ([string](Get-Location).Path) $OutDir
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
$oldSeed = $env:GO_OBF_SEED
try {
    $powerShell = Join-Path $PSHOME "pwsh.exe"
    if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
        $powerShell = Join-Path $PSHOME "powershell.exe"
    }
    if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
        throw "PowerShell host was not found for the negative fixture"
    }
    foreach ($negative in @(
        [pscustomobject]@{ Name = "v4"; Fixture = "v4negative" },
        [pscustomobject]@{ Name = "v5"; Fixture = "v5negative" }
    )) {
        $negativeFixture = Join-Path $PSScriptRoot ("testdata\" + $negative.Fixture)
        $negativeArtifact = Join-Path $OutDir ($negative.Fixture + ".exe")
        $negativeCache = Join-Path $OutDir ($negative.Fixture + "-cache")
        Remove-Item -LiteralPath $negativeArtifact -Force -ErrorAction SilentlyContinue
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        $env:GO_OBF_SEED = ($negative.Name + "-negative-matrix")
        $negativeOutput = @()
        $negativeExitCode = 0
        Push-Location $negativeFixture
        try {
            $negativeOutput = @(& $powerShell -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot "build.ps1") `
                -Package . `
                -Out $negativeArtifact `
                -Cache $negativeCache `
                -VMBudget 512 2>&1)
            $negativeExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        $negativeText = (@($negativeOutput | ForEach-Object { [string]$_ }) -join "`n")
        if ($negativeExitCode -eq 0) {
            throw "String $($negative.Name) negative fixture unexpectedly compiled"
        }
        if ($negativeText -notmatch "StaticLECall") {
            throw "String $($negative.Name) negative fixture failed without the expected escape diagnostic"
        }
        if (Test-Path -LiteralPath $negativeArtifact -PathType Leaf) {
            throw "String $($negative.Name) negative fixture published an artifact after rejection"
        }
        Write-Output "negative pass: $($negative.Name) stream escape rejected (exit=$negativeExitCode)"
    }

    $nativeArtifact = Join-Path $OutDir "nativecfg.exe"
    $nativeProfile = Join-Path $OutDir "nativecfg.profile.json"
    $nativeManifest = Join-Path $OutDir "nativecfg.manifest.json"
    $nativeCache = Join-Path $OutDir "nativecfg-cache"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $env:GO_OBF_SEED = "nativecfg-matrix-windows-amd64"
    Push-Location $nativeFixture
    try {
        & (Join-Path $PSScriptRoot "build.ps1") `
            -Package . `
            -Out $nativeArtifact `
            -Report $nativeProfile `
            -Manifest $nativeManifest `
            -Cache $nativeCache `
            -VMBudget 512 `
            -NativeBudget 48 `
            -SSACheck
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
    $nativeVerifyArgs = @{
        Artifact = $nativeArtifact
        Profile = $nativeProfile
        Manifest = $nativeManifest
        CompilerRoot = $root
        RequireCompilerBinary = $true
        RequireCompilerSource = $true
        RequireTooling = $true
        RequireRuntimeGuardV3 = $true
        RequireNativeCFG = $true
        RequireNativeCFGFull = $true
        RequireFunction = @("main.nativeBranch", "main.nativeLoopCall", "main.nativeDefer", "main.nativeBool", "main.nativeZeroArg")
        MinReportFunctions = 5
    }
    if ($RequireCleanCompiler) {
        $nativeVerifyArgs.RequireCleanCompiler = $true
    }
    & (Join-Path $PSScriptRoot "verify.ps1") @nativeVerifyArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($env:OS -eq "Windows_NT") {
        & $nativeArtifact
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    Write-Output "matrix pass: native CFG v2 windows/amd64"

    foreach ($tuple in $Target) {
        if ($tuple -notmatch '^([a-z0-9]+)/(\w+)$') {
            throw "invalid target tuple: $tuple"
        }
        $goos = $Matches[1]
        $goarch = $Matches[2]
        $name = "$goos-$goarch"
        $env:GOOS = $goos
        $env:GOARCH = $goarch
        $env:CGO_ENABLED = "0"
        $env:GO_OBF_SEED = "v38-matrix-$name"

        $artifactSuffix = if ($goos -eq "windows") { ".exe" } else { "" }
        $artifact = Join-Path $OutDir ("$name" + $artifactSuffix)
        $profile = Join-Path $OutDir "$name.profile.json"
        $manifest = Join-Path $OutDir "$name.manifest.json"
        Push-Location $fixture
        try {
            & (Join-Path $PSScriptRoot "build.ps1") `
                -Package . `
                -Out $artifact `
                -Report $profile `
                -Manifest $manifest `
                -VMBudget 2048 `
                -ScanPlaintext @("v38-cross-platform-ephemeral", "v4-stream-byte-check", "v5-lease-stream-check")
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } finally {
            Pop-Location
        }

        $profileObject = Get-Content -LiteralPath $profile -Raw | ConvertFrom-Json
        $verifyArgs = @{
            Artifact = $artifact
            Profile = $profile
            Manifest = $manifest
            CompilerPath = [string]$profileObject.compiler.path
            CompilerRoot = $root
            RequireCompilerBinary = $true
            RequireCompilerSource = $true
            RequireTooling = $true
            RequireRuntimeChecks = $true
            RequireRuntimeGuardV3 = $true
            RequireStringV4 = $true
            RequireStringV5 = $true
            RequireFunction = @("main.vmCalc", "main.secretCheck", "main.streamCheck", "main.leaseStreamCheck")
            MinReportFunctions = 4
            MinV4Aliases = 1
            ExpectedAbsent = @("v38-cross-platform-ephemeral", "v4-stream-byte-check", "v5-lease-stream-check")
            ForbiddenMetadata = @($env:GO_OBF_SEED, $root, $fixture)
        }
        if ($RequireCleanCompiler) {
            $verifyArgs.RequireCleanCompiler = $true
        }
        & (Join-Path $PSScriptRoot "verify.ps1") @verifyArgs
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        if ($goos -eq "windows" -and $goarch -eq "amd64" -and $env:OS -eq "Windows_NT") {
            & $artifact
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        Write-Output "matrix pass: $tuple"
    }
} finally {
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:CGO_ENABLED = $oldCgo
    $env:GO_OBF_SEED = $oldSeed
}
