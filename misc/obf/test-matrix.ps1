param(
    [string[]]$Target = @("windows/amd64", "linux/amd64", "linux/arm64"),
    [string]$OutDir = "",
    [switch]$RequireCleanCompiler
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$fixture = Join-Path $PSScriptRoot "testdata\v38matrix"
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

        $artifact = Join-Path $OutDir "$name.exe"
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
                -ScanPlaintext @("v38-cross-platform-ephemeral", "v4-stream-byte-check")
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
            RequireFunction = @("main.vmCalc", "main.secretCheck", "main.streamCheck")
            MinReportFunctions = 3
            MinV4Aliases = 1
            ExpectedAbsent = @("v38-cross-platform-ephemeral", "v4-stream-byte-check")
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
