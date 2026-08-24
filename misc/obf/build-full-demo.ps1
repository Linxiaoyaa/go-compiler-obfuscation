param(
    [string]$OutDir = "",
    [string]$Seed = "full-protect-demo-v1",
    [string]$LinuxCC = ""
)

$ErrorActionPreference = "Stop"

function Resolve-UserPath {
    param([string]$Value)

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path ([string](Get-Location).Path) $Value))
}

function Restore-EnvironmentValue {
    param(
        [string]$Name,
        [object]$Value
    )

    if ($null -eq $Value) {
        Remove-Item ("Env:" + $Name) -ErrorAction SilentlyContinue
    } else {
        Set-Item ("Env:" + $Name) $Value
    }
}

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\\.."))
$fixture = Join-Path $PSScriptRoot "testdata\\fullrelease"
$build = Join-Path $PSScriptRoot "build.ps1"
$verify = Join-Path $PSScriptRoot "verify.ps1"
if (-not $OutDir) {
    $OutDir = Join-Path $root "work\\full-protect-demo"
} else {
    $OutDir = Resolve-UserPath -Value $OutDir
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

if (-not $LinuxCC) {
    $zig = Get-Command zig -ErrorAction Stop
    $LinuxCC = ('"' + $zig.Source + '" cc -target x86_64-linux-gnu')
}

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
$oldCC = $env:CC
try {
    $plaintext = @(
        "full-ephemeral-v3",
        "full-stream-byte-v4",
        "full-lease-token-v5",
        "full-ticket-token-v6"
    )
    Push-Location $fixture
    try {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "1"
        $env:CC = $oldCC
        & $build `
            -Package . `
            -Out (Join-Path $OutDir "full-protect.exe") `
            -Report (Join-Path $OutDir "full-protect.exe.profile.json") `
            -Manifest (Join-Path $OutDir "full-protect.exe.manifest.json") `
            -BuildMode exe `
            -Seed $Seed `
            -VMBudget 2048 `
            -ScanPlaintext $plaintext
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    $exeProfile = Get-Content -LiteralPath (Join-Path $OutDir "full-protect.exe.profile.json") -Raw | ConvertFrom-Json
    & $verify `
        -Artifact (Join-Path $OutDir "full-protect.exe") `
        -Profile (Join-Path $OutDir "full-protect.exe.profile.json") `
        -Manifest (Join-Path $OutDir "full-protect.exe.manifest.json") `
        -CompilerPath $exeProfile.compiler.path `
        -CompilerRoot $root `
        -RequireCompilerBinary -RequireCompilerSource -RequireTooling `
        -RequireRuntimeGuardV4 -RequireStringV4 -RequireStringV5 -RequireStringV6 -RequireResidualScan `
        -RequireFunction @("main.vmMix", "main.ephemeralCheck", "main.streamCheck", "main.leaseCheck", "main.ticketCheck", "main.encryptedInput") `
        -MinReportFunctions 6 -MinV4Aliases 1 `
        -ExpectedAbsent $plaintext `
        -ForbiddenMetadata @($root, $fixture)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & (Join-Path $OutDir "full-protect.exe")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Push-Location $fixture
    try {
        $env:GOOS = "linux"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "1"
        $env:CC = $LinuxCC
        & $build `
            -Package . `
            -Out (Join-Path $OutDir "full-protect.so") `
            -Report (Join-Path $OutDir "full-protect.so.profile.json") `
            -Manifest (Join-Path $OutDir "full-protect.so.manifest.json") `
            -BuildMode c-shared `
            -Seed $Seed `
            -VMBudget 2048 `
            -ScanPlaintext $plaintext
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    $soPath = Join-Path $OutDir "full-protect.so"
    $soProfilePath = Join-Path $OutDir "full-protect.so.profile.json"
    $soManifestPath = Join-Path $OutDir "full-protect.so.manifest.json"
    $soProfile = Get-Content -LiteralPath $soProfilePath -Raw | ConvertFrom-Json
    & $verify `
        -Artifact $soPath `
        -Profile $soProfilePath `
        -Manifest $soManifestPath `
        -CompilerPath $soProfile.compiler.path `
        -CompilerRoot $root `
        -RequireCompilerBinary -RequireCompilerSource -RequireTooling `
        -RequireRuntimeGuardV4 -RequireStringV4 -RequireStringV5 -RequireStringV6 -RequireResidualScan -RequireCHeader `
        -RequireFunction @("main.vmMix", "main.ephemeralCheck", "main.streamCheck", "main.leaseCheck", "main.ticketCheck", "main.encryptedInput") `
        -MinReportFunctions 6 -MinV4Aliases 1 `
        -ExpectedAbsent $plaintext `
        -ForbiddenMetadata @($root, $fixture)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $soMagic = [System.IO.File]::ReadAllBytes($soPath)
    if ($soMagic.Length -lt 4 -or $soMagic[0] -ne 0x7f -or $soMagic[1] -ne 0x45 -or $soMagic[2] -ne 0x4c -or $soMagic[3] -ne 0x46) {
        throw "shared library does not have an ELF header"
    }
    $headerPath = Join-Path $OutDir "full-protect.h"
    if (-not (Select-String -LiteralPath $headerPath -Pattern "FullProtectVerify" -Quiet)) {
        throw "generated C header does not declare FullProtectVerify"
    }
    $nm = Get-Command nm -ErrorAction Stop
    $nmOutput = @(& $nm.Source -D --defined-only $soPath 2>&1)
    if ($LASTEXITCODE -ne 0 -or (($nmOutput -join "`n") -notmatch "FullProtectVerify")) {
        throw "shared library does not export FullProtectVerify"
    }
    Write-Output "full protection demo passed: $OutDir"
} finally {
    Restore-EnvironmentValue -Name "GOOS" -Value $oldGoos
    Restore-EnvironmentValue -Name "GOARCH" -Value $oldGoarch
    Restore-EnvironmentValue -Name "CGO_ENABLED" -Value $oldCgo
    Restore-EnvironmentValue -Name "CC" -Value $oldCC
}
