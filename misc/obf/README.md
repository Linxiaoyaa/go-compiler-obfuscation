# Go protection compiler v6.0 (String v6 + Runtime Guard v4)

This compiler fork recognizes function directives that remain valid Go source:

```go
//go:obf
//go:encrypt
func nativeCalc(a, b uint64) uint64 {
	return (a + 0x1122334455667788) ^ (b * 7)
}

//go:vm
//go:encrypt
func vmCalc(a, b uint64) uint64 {
	return (a ^ 0x1234) + b
}

//go:noprotect
func exportedBridge(a, b uint64) uint64 {
	return a + b
}
```

## Directives

- `//go:obf`: inserts seed-derived opaque control-flow layers for native (non-VM) functions.
- `//go:encrypt`: encodes live `uint64` constants and encrypts non-empty string literals in marked non-VM functions.
- `//go:vm`: translates supported pure SSA into a per-function register-threaded VM v4 dispatcher.
- `//go:ephemeral`: combines with `//go:encrypt` for a short-lived string literal. The function cannot return string values; the compiler proves that decoded storage stays local and inserts a wipe on every normal return. A runtime cleanup remains for the exceptional GC path.
- `//go:stream`: combines with `//go:encrypt` for String v4. It permits only local `len` and byte-index reads, replaces each read with a bounded single-byte decoder, and rejects calls, stores, comparisons, interfaces, maps, channels, returns, and other string/pointer escapes. It cannot be combined with `//go:ephemeral` or `//go:vm`.
- `//go:streamv5`: combines with `//go:encrypt` for a lease-bound String v5 byte stream. It has the same strict local `len` and byte-read boundary as v4, but uses separate ciphertext, mask, and lease domains. It cannot be combined with `//go:ephemeral`, `//go:stream`, or `//go:vm`.
- `//go:streamv6`: combines with `//go:encrypt` for a ticket-bound String v6 byte stream. It retains the v5 local `len` and byte-read boundary, adds an independently derived ticket to each token and byte decoder, and cannot be combined with `//go:ephemeral`, `//go:stream`, `//go:streamv5`, or `//go:vm`.
- `//go:noprotect`: explicitly excludes the function and cannot be combined with the other directives.

Protected functions are automatically excluded from inlining. Explicit directives are strict: unsupported functions fail compilation instead of silently losing protection.

## Symbol names

The build script enables Garble-inspired deterministic symbol hashing by default. Explicitly protected, non-exported Go functions are emitted under an `obf.fn.<digest>` linker name derived from the seed, package path, and source function name. The source name remains available to compiler diagnostics. `main`, `init`, ABI-sensitive functions, existing `//go:linkname` declarations, exported names, methods, and runtime functions retain stable identities.

The linker then removes valid `obf.fn.<32 hex digits>` names and their linker-generated trampoline derivatives from `runtime.funcnametab` by mapping their `_func.nameOff` field to the reserved empty-name entry. This closes the remaining name leak after `-s -w` removes the ordinary symbol table and DWARF: protected functions appear unnamed through `runtime.FuncForPC` and pclntab-based reverse-engineering tools, while their entry addresses and file/line metadata remain usable. Pass `-KeepPclnNames` to retain hashed runtime names for diagnostics, or `-NoObfuscateNames` to retain original names throughout the build.

By default the linker also encodes every `_func.entryOff` with a seed-derived odd 32-bit key and a per-record domain. The runtime decodes it only when the linker patches `runtime.obfEntryOffKey`, so ordinary Go builds and tools remain compatible. This mode is limited to standalone executable and PIE outputs; use `-NoObfuscateEntryOff` for a raw-entry diagnostic build.

The linker also uses a seed-derived `pclntab` magic for protected executable/PIE builds and patches the matching runtime verifier value. This prevents tools that assume the stock Go magic from recognizing the table immediately. Use `-NoObfuscateMagic` for a standard-magic diagnostic build.

Protected builds also pass a seed-derived value to the linker's existing function-layout randomizer. The final text order is reproducible for a fixed seed and changes when the seed changes. Use `-NoRandomizeLayout` when profiling or comparing stable addresses.

The runtime `pclntab.filetab` entries are replaced with deterministic `obf.src.<hash>` names derived from the seed and full source path. This hides source file paths from runtime stack metadata while preserving line numbers. The transformation is limited to `pclntab`; DWARF paths remain available when `-KeepSymbols` is used. Pass `-NoObfuscateFileNames` to retain original runtime file names.

This is deliberately narrower than the full Garble source transformer: it does not rewrite exported APIs, struct fields, package paths, or reflection-visible identifiers. That boundary keeps ordinary cross-package Go builds and interface dispatch compatible while the protected implementation symbols are hidden.

## String literals

For a non-VM function marked `//go:encrypt`, each non-empty string literal is replaced with a ciphertext symbol whose name is a digest. String v2 derives four key lanes through separate build, function, literal, and mask domains using SHA-256 length-prefixed inputs. The compiler selects one of four independently named and implemented runtime decoder entries (`obfStringDataV2A` through `obfStringDataV2D`) from the literal domain.

The selected decoder allocates the final backing storage and writes plaintext directly into it. There is no complete temporary plaintext copy or process-wide plaintext cache, and the decoder overwrites its stack key schedule before returning. A returned Go string is still immutable: plaintext remains wherever the caller keeps that string alive, so sensitive values should be consumed in a short scope rather than stored globally.

Functions that also contain control flow or memory operations, such as map and container initialization, use block-local constant decoder chains on 64-bit targets. This keeps compiler-generated live `uint64` constants encoded without moving their decoded values across invalid SSA ownership boundaries.

The returned Go string remains plaintext for as long as the program retains it; the runtime cannot erase a still-live immutable string without breaking program semantics. Keep sensitive strings scoped to the operation that consumes them and avoid storing them in globals or long-lived objects. If the same literal also appears in an unprotected function or global initializer, that unprotected occurrence can still place plaintext in the binary.

String v3 is selected by `//go:ephemeral` and uses separate derivation and ciphertext domains. It rejects values that escape through a return, heap store, call, interface, map, channel, or global. The directive is deliberately explicit because the compiler cannot infer a universally safe last use for an immutable Go string.

String v4 is selected by `//go:stream`. Its emitted string header points only to ciphertext; an SSA pass replaces approved byte loads with one of four bounded byte decoders and changes `len` uses to the known ciphertext length. The decoder validates its index, derives one byte, wipes its short-lived key lanes, and does not allocate or materialize a complete plaintext string. This mode is intentionally narrow: it is for byte-wise comparisons and parsers that can consume secret text incrementally.

String v5 is selected by `//go:streamv5`. It keeps the v4 local-only SSA boundary but derives ciphertext and each byte mask from independent v5 root, literal, mask, and lease domains. The byte decoder combines the lease with a temporary per-byte key, zeros both before return, and never materializes a complete plaintext string. Use it where a caller can consume the value byte by byte and the additional per-read derivation cost is acceptable.

String v6 is selected by `//go:streamv6`. It retains the v5 local-only SSA boundary, four key lanes, and lease while deriving a separate ticket capability. The runtime validates both capability words at token and byte boundaries, wipes the key lanes, lease, and ticket before returning each byte, and never materializes a complete plaintext string. Use it for byte-wise checks where the additional per-read ticket derivation cost is acceptable.

## VM v4 boundary

VM v4 accepts pure functions with at least one `uint64` argument and one scalar result (`uint64` or `bool`). It preserves multiple plain/conditional blocks, loops, and Phi values by assigning virtual registers on dispatcher edges. Supported operations are arguments, `uint64` constants, copy, add, subtract, multiply, bitwise AND/OR/XOR, left shift by `uint64`, unsigned right shift by `uint64`, negate, complement, equality/inequality, unsigned less-than/less-or-equal, boolean AND/OR/equality/inequality/NOT, and conditional select.

VM v4 fuses up to eight consecutive pure calculations into seed-dependent super-instructions before installing the dispatcher. Safe jump and return terminators may share the final handler; conditional terminators stay separate so short-circuit and Phi-result semantics remain exact. States are balanced across 1, 2, 4, or 8 dispatch buckets, and each bucket independently shuffles real and decoy checks. Bounded independently seeded alias checks reduce the regularity of the dispatcher without unbounded compiler growth. `-d=obfseed=<seed>` reproduces a build; changing the seed changes fusion widths, bucket membership, check order, decoy states, encoded constants, string key lanes, ciphertext, and decoder selection.

`-d=obfreport=1` emits one `OBFREPORT` line per marked function. VM v4 reports source instruction count, fused state count, terminal fusions, bucket/check/decoy/alias counts, budget, and pre/post CFG shape. The build script prints total elapsed build time.

`-VMBudget` (or `-d=obfv4budget`) caps estimated VM dispatcher growth; reports include `aliases=` and `budget=` so the verifier can enforce a minimum without allowing unbounded compile-time expansion.

Native `//go:obf` uses CFG opaque-dispatch v3. Eligible plain, conditional, defer-continuation, jump-table, and reachable `BlockFirst` edges are routed through a seed-derived opaque branch with asymmetric direct and detour/relay paths, while retaining the original Phi predecessor slot and memory chain. The `-NativeBudget` (or `-d=obfnativebudget`) is a total per-function layer budget, defaulting to 48: v3 first covers edges, then distributes remaining budget across at most three layers per covered edge. `OBFREPORT` records `coverage=full` or `coverage=budgeted`, edge/block counts, `layers=`, and `max-depth=` so partial coverage and depth are explicit. `build.ps1 -SSACheck` adds the compiler SSA invariant pass for the selected package, and `verify.ps1 -RequireNativeCFG -RequireNativeCFGFull` enforces the resulting release evidence.

`testdata/nativecfg` is a focused executable regression fixture for native CFG v3. It covers multi-block branch, loop-plus-call, `defer`, switch jump tables, multiple returns, and `panic/recover`; it is suitable for builds with `-d=ssa/check/on` because it does not exercise the string transforms.

Protected release builds inject a `runtime=entry-v4` gate at every protected function entry. The linker writes independent 64-bit bootstrap, image-low, image-high, target-platform, and metadata-key words in addition to the entry-offset key and custom `pclntab` magic; after generating `runtime.pclntab`, it derives a metadata seal from the final function count, file count, and pclntab length. The gate validates module bounds, all static fields, the final metadata seal, and the function-local seal. It records the first valid binding atomically but rechecks both static and pclntab-derived state at every protected entry, so cached success cannot mask a later metadata edit. The normal build path enables it automatically; `-NoRuntimeChecks` disables it, and diagnostic builds that use `-NoObfuscateEntryOff` or `-NoObfuscateMagic` disable it because those options intentionally remove part of the bound runtime state.

Pointer-bearing registers, signed/narrow integer conversions, multiple returns, memory operations, calls, interfaces, `defer`, `panic/recover`, jump tables, and strings remain outside the VM boundary. String literals are supported by `//go:encrypt` only on the native non-VM path. An explicitly marked function that crosses the VM boundary fails compilation with a diagnostic; it is never silently emitted without the requested VM transform.

## Build

From the target module directory:

```powershell
D:\Projection\GoProject\go-compiler\misc\obf\build.ps1 `
  -Package .\cmd\app `
  -Out .\dist\app-protected.exe `
  -Pattern 'example.com/module/...' `
  -ScanPlaintext @('literal-that-must-not-appear')
```

The script generates a random seed unless `-Seed` is supplied, strips symbols by default, hashes protected linker symbols, removes those hashes and their linker trampoline derivatives from runtime pclntab, hashes runtime source file names, encodes function entry offsets, customizes the pclntab magic, writes Runtime Guard v4 image/platform/metadata bindings, enables entry integrity checks, randomizes function layout, and uses a dedicated isolated build cache. Each `-ScanPlaintext` and metadata value is searched in the completed artifact as UTF-8 and UTF-16LE, with raw and slash-normalized forms; any match fails the build. The default residual scan also covers the seed, compiler root, current path, and every `name=hash-v1` function reported by the compiler, including common wrapper suffixes. Use `-KeepPclnNames` for hashed-name diagnostics, `-NoObfuscateNames` for a stable-name diagnostic build, `-NoObfuscateEntryOff` to inspect raw entry offsets, `-NoObfuscateMagic` to retain the standard pclntab magic, `-NoRuntimeChecks` to remove entry gates, `-NoRandomizeLayout` for stable function order, or `-NoObfuscateFileNames` for original runtime file names. The separate cache is required because this fork adds versioned protection fields to unified IR export data.

`-BuildMode` accepts `default`, `exe`, `pie`, and `c-shared`. The c-shared path receives the same encoded pclntab, Runtime Guard v4, layout, filename, and protected-name treatment as EXE/PIE. It forwards stripping to the external ELF linker, publishes the generated C header alongside the library, and records both header and build mode in the profile and manifest.

### Full EXE and SO demo

The checked-in `testdata/fullrelease` module demonstrates the strongest compatible directive coverage: VM v4, native constant encryption, String v3/v4/v5/v6, Runtime Guard v4, hidden protected names, encoded entry offsets, custom pclntab magic, randomized layout, and hashed source metadata. The C ABI bridge and executable launcher contain no secrets because cgo ABI and multi-block entry functions are outside the current strict SSA directive boundary.

```powershell
& 'D:\Projection\GoProject\go-compiler\misc\obf\build-full-demo.ps1' `
  -OutDir .\work\full-protect-demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

On Windows, the script executes the generated `full-protect.exe`, then uses Zig to cross-build `full-protect.so` for Linux AMD64. It requires `zig` and a GNU/LLVM-compatible `nm` on `PATH`. It verifies both release records, scans protected plaintext values, validates the ELF header, validates the generated `full-protect.h`, confirms the required dynamic C export, and requires strict Runtime Guard v4 plus String v4/v5/v6 coverage.

### Build profiles and independent verification

Pass `-Report <path>` to write a `go-obf-profile/v2` JSON profile after a successful build. The profile records the compiler version, binary hash, source-tree digest and revision, target tuple, final pattern, protection modes, artifact size/hash/elapsed time, marker offsets/counts, parsed `OBFREPORT` summaries, and digest-only plaintext, metadata, and compiler-derived residual scan results. Pass `-Manifest <path>` to additionally write a `go-obf-release-manifest/v1` record binding artifact/profile/compiler/source/target/seed fingerprints. The profile and manifest also bind the build, verification, matrix, and integrity-test scripts by SHA-256. The raw seed is never written to the profile or compiler command line when the default environment-seed path is used. Relative `-Out`, `-Report`, `-Manifest`, `-Cache`, and `-SeedFile` paths resolve against the caller's current directory. The linker output, profile, and manifest are prepared in same-directory temporary files and published only after compilation and scans succeed.

Seed input precedence is `-Seed`, then `-SeedFile`, then the environment variable named by `-SeedEnv` (default `GO_OBF_SEED`), then a generated random seed. For release builds prefer `-SeedFile` or `GO_OBF_SEED`; the script prints only a SHA-256 fingerprint by default. `-ShowSeed` is intended for local diagnostics and restores the raw value in console output. The compiler receives the seed through `-d=obfseedenv=GO_OBF_SEED`; `obfseedid=<fingerprint>` separates build-cache entries without exposing the seed in compiler arguments.

```powershell
$build = 'D:\Projection\GoProject\go-compiler\misc\obf\build.ps1'
& $build `
  -Package . `
  -Out .\dist\app-protected.exe `
  -Report .\dist\app-protected.profile.json `
  -Manifest .\dist\app-protected.manifest.json `
  -Pattern 'example.com/module/...' `
  -ScanPlaintext @('literal-that-must-not-appear') `
  -ScanMetadata @('source-root-or-build-marker')

$profile = Get-Content .\dist\app-protected.profile.json -Raw | ConvertFrom-Json
& 'D:\Projection\GoProject\go-compiler\misc\obf\verify.ps1' `
  -Artifact .\dist\app-protected.exe `
  -Profile .\dist\app-protected.profile.json `
  -Manifest .\dist\app-protected.manifest.json `
  -CompilerPath $profile.compiler.path `
  -CompilerRoot 'D:\Projection\GoProject\go-compiler' `
  -RequireCompilerBinary -RequireCompilerSource -RequireRuntimeGuardV4 -RequireResidualScan `
  -ForbiddenMetadata @('source-root-or-build-marker') `
  -ExpectedAbsent @('literal-that-must-not-appear')
```

For a release pipeline, keep the seed outside the command line and bind verification to an external digest and coverage manifest:

```powershell
$env:GO_OBF_SEED = Get-Content .\secrets\obf-seed.txt -Raw
& $build -Package . -Out .\dist\app.exe -Report .\dist\app.profile.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& 'D:\Projection\GoProject\go-compiler\misc\obf\verify.ps1' `
  -Artifact .\dist\app.exe `
  -Profile .\dist\app.profile.json `
  -ExpectedSha256 $env:EXPECTED_ARTIFACT_SHA256 `
  -ExpectedProfileSha256 $env:EXPECTED_PROFILE_SHA256 `
  -ExpectedSeedFingerprint $env:EXPECTED_OBF_SEED_FINGERPRINT `
  -ExpectedCompilerSha256 $env:EXPECTED_COMPILER_SHA256 `
  -ExpectedCompilerCommit $env:EXPECTED_COMPILER_COMMIT `
  -RequireCleanCompiler `
  -RequireFunction 'example.com/module/internal.process' `
  -MinReportFunctions 1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

`verify.ps1` emits one machine-readable JSON result and exits `0` only when every applicable check passes. It independently checks the profile schema, artifact path/size/SHA-256, optional externally supplied artifact/compiler/seed fingerprints, required function coverage, hidden or retained protected names, hashed pclntab source names, the recorded pclntab magic, the encoded entry-key marker, compiler-derived protected-name residuals, and any `-ForbiddenText`/`-ExpectedAbsent` values. `-RequireRuntimeGuardV4` requires `entry-v4` coverage plus image, platform, metadata-key, and pclntab-derived metadata-seal marker records; `-RequireRuntimeChecks` remains compatible with legacy profiles. `-RequireStringV4`, `-RequireStringV5`, and `-RequireStringV6` require their respective profile markers and at least one matching protected function. `-RequireResidualScan` requires digest-only zero-match UTF-8/UTF-16LE records and rechecks all compiler-derived protected names. Function-name checks use the compiler's `name=hash-v1` report marker, so exported APIs that intentionally retain stable names are recorded as compatibility skips. The profile stores only hashes for build-time plaintext scans, so pass those values again when the verifier must rescan them; without them the result marks that check as `skip` instead of claiming an independent scan. A mismatched artifact or profile exits `1`; a missing/invalid profile or artifact exits `2`.

`test-integrity.ps1` exercises the release verifier against an untouched copied record plus nine intentional changes: artifact bytes, a self-consistent UTF-16LE residual metadata insertion, manifest artifact hash, compiler binary hash, compiler source digest, seed fingerprint, disabled runtime checks, a self-consistent v4-to-v2 runtime downgrade, and the Runtime Guard v4 marker. It expects each modified case to fail on its named verifier check, then exits `0` only when the complete negative suite behaves as expected.

```powershell
$profile = Get-Content .\dist\app-protected.profile.json -Raw | ConvertFrom-Json
& 'D:\Projection\GoProject\go-compiler\misc\obf\test-integrity.ps1' `
  -Artifact .\dist\app-protected.exe `
  -Profile .\dist\app-protected.profile.json `
  -Manifest .\dist\app-protected.manifest.json `
  -CompilerPath $profile.compiler.path `
  -CompilerRoot 'D:\Projection\GoProject\go-compiler'
```

For CI, make the verifier a separate step so a changed executable cannot reuse an old successful build result:

```powershell
& $build -Package . -Out $env:CI_ARTIFACT -Report $env:CI_PROFILE -Seed $env:OBF_SEED
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& 'D:\Projection\GoProject\go-compiler\misc\obf\verify.ps1' `
  -Artifact $env:CI_ARTIFACT `
  -Profile $env:CI_PROFILE `
  -ExpectedAbsent $env:OBF_FORBIDDEN_TEXT
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

### Cross-platform and negative coverage

`test-matrix.ps1` runs the protected fixture for `windows/amd64`, `linux/amd64`, `linux/arm64`, `linux/riscv64`, `darwin/amd64`, and `darwin/arm64` (override with `-Target`). It builds and verifies every tuple, and executes the Windows AMD64 artifact on a Windows host. It also builds and executes the native CFG v3 fixture with SSA checking. Before the positive matrix it compiles `testdata/v4negative`, `testdata/v5negative`, and `testdata/v6negative`, with their stream directives applied to a string comparison, and requires the compiler to reject the `StaticLECall` escape diagnostic. A zero exit, a missing diagnostic, or a published artifact fails the matrix. The negative checks use fixed seeds and isolated caches so they are reproducible and do not affect release artifacts.

```powershell
& 'D:\Projection\GoProject\go-compiler\misc\obf\test-matrix.ps1' `
  -OutDir .\work\v6-cross-platform
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```
