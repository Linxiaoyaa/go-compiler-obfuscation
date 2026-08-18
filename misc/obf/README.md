# Go protection compiler v2.2

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
- `//go:vm`: translates supported pure SSA into a per-function register-threaded VM dispatcher.
- `//go:noprotect`: explicitly excludes the function and cannot be combined with the other directives.

Protected functions are automatically excluded from inlining. Explicit directives are strict: unsupported functions fail compilation instead of silently losing protection.

## String literals

For a non-VM function marked `//go:encrypt`, each non-empty string literal is replaced with a seed- and function-derived ciphertext symbol. The compiler emits a call to `runtime.obfStringData`, which allocates the final backing storage and decodes directly into it. There is no complete temporary plaintext copy and no process-wide plaintext cache.

Functions that also contain control flow or memory operations, such as map and container initialization, use block-local constant decoder chains on 64-bit targets. This keeps compiler-generated live `uint64` constants encoded without moving their decoded values across invalid SSA ownership boundaries.

The returned Go string remains plaintext for as long as the program retains it; the runtime cannot erase a still-live immutable string without breaking program semantics. Keep sensitive strings scoped to the operation that consumes them and avoid storing them in globals or long-lived objects. If the same literal also appears in an unprotected function or global initializer, that unprotected occurrence can still place plaintext in the binary.

## VM v2 boundary

VM v2 accepts pure functions with at least one `uint64` argument and one scalar result (`uint64` or `bool`). It preserves multiple plain/conditional blocks, loops, and Phi values by assigning virtual registers on dispatcher edges. Supported operations are arguments, `uint64` constants, copy, add, subtract, multiply, bitwise AND/OR/XOR, left shift by `uint64`, unsigned right shift by `uint64`, negate, complement, equality/inequality, unsigned less-than/less-or-equal, boolean AND/OR/equality/inequality/NOT, and conditional select.

The VM uses deterministic per-function randomized state values, a seed-dependent check order, and an encoded invalid-state sink. Each dispatcher also includes unreachable decoy checks (about half as many as real states) whose hit path joins the invalid-state sink. `-d=obfseed=<seed>` reproduces a build; changing the seed changes dispatcher order, decoy states, and encoded constants. `-d=obfreport=1` emits one `OBFREPORT` line per marked function, including the real check and decoy counts.

Pointer-bearing registers, signed/narrow integer conversions, multiple returns, memory operations, calls, interfaces, `defer`, `panic/recover`, jump tables, and strings remain outside the VM boundary. String literals are supported by `//go:encrypt` only on the native non-VM path. An explicitly marked function that crosses the VM boundary fails compilation with a diagnostic; it is never silently emitted without the requested VM transform.

## Build

From the target module directory:

```powershell
D:\Projection\GoProject\go-compiler\misc\obf\build.ps1 `
  -Package .\cmd\app `
  -Out .\dist\app-protected.exe `
  -Pattern 'example.com/module/...'
```

The script generates a random seed unless `-Seed` is supplied, strips symbols by default, and uses a dedicated V3 build cache. The separate cache is required because this fork adds a versioned per-function field to unified IR export data.
