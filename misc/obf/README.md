# Go protection compiler v3.1 (String v2)

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

- `//go:obf`: inserts an opaque control-flow diamond for native (non-VM) functions.
- `//go:encrypt`: encodes live `uint64` constants and encrypts non-empty string literals in marked non-VM functions.
- `//go:vm`: translates supported pure SSA into a per-function register-threaded VM v3 dispatcher.
- `//go:noprotect`: explicitly excludes the function and cannot be combined with the other directives.

Protected functions are automatically excluded from inlining. Explicit directives are strict: unsupported functions fail compilation instead of silently losing protection.

## String literals

For a non-VM function marked `//go:encrypt`, each non-empty string literal is replaced with a ciphertext symbol whose name is a digest. String v2 derives four key lanes through separate build, function, literal, and mask domains using SHA-256 length-prefixed inputs. The compiler selects one of four independently named and implemented runtime decoder entries (`obfStringDataV2A` through `obfStringDataV2D`) from the literal domain.

The selected decoder allocates the final backing storage and writes plaintext directly into it. There is no complete temporary plaintext copy or process-wide plaintext cache, and the decoder overwrites its stack key schedule before returning. A returned Go string is still immutable: plaintext remains wherever the caller keeps that string alive, so sensitive values should be consumed in a short scope rather than stored globally.

Functions that also contain control flow or memory operations, such as map and container initialization, use block-local constant decoder chains on 64-bit targets. This keeps compiler-generated live `uint64` constants encoded without moving their decoded values across invalid SSA ownership boundaries.

The returned Go string remains plaintext for as long as the program retains it; the runtime cannot erase a still-live immutable string without breaking program semantics. Keep sensitive strings scoped to the operation that consumes them and avoid storing them in globals or long-lived objects. If the same literal also appears in an unprotected function or global initializer, that unprotected occurrence can still place plaintext in the binary.

## VM v3 boundary

VM v3 accepts pure functions with at least one `uint64` argument and one scalar result (`uint64` or `bool`). It preserves multiple plain/conditional blocks, loops, and Phi values by assigning virtual registers on dispatcher edges. Supported operations are arguments, `uint64` constants, copy, add, subtract, multiply, bitwise AND/OR/XOR, left shift by `uint64`, unsigned right shift by `uint64`, negate, complement, equality/inequality, unsigned less-than/less-or-equal, boolean AND/OR/equality/inequality/NOT, and conditional select.

VM v3 fuses up to eight consecutive pure calculations into seed-dependent super-instructions before installing the dispatcher. Safe jump and return terminators may share the final handler; conditional terminators stay separate so short-circuit and Phi-result semantics remain exact. States are balanced across 1, 2, 4, or 8 dispatch buckets, and each bucket independently shuffles real and decoy checks. This replaces the single recognizable linear state chain while reducing state, check, and handler counts. `-d=obfseed=<seed>` reproduces a build; changing the seed changes fusion widths, bucket membership, check order, decoy states, encoded constants, string key lanes, ciphertext, and decoder selection.

`-d=obfreport=1` emits one `OBFREPORT` line per marked function. VM v3 reports source instruction count, fused state count, terminal fusions, bucket/check/decoy counts, and pre/post CFG shape. String v2 is reported as `encrypt=str-runtime-v2`. The build script prints total elapsed build time.

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

The script generates a random seed unless `-Seed` is supplied, strips symbols by default, and uses a dedicated V4 build cache. Each `-ScanPlaintext` value is searched as UTF-8 bytes in the completed executable; any match fails the build. The separate cache is required because this fork adds versioned protection fields to unified IR export data.
