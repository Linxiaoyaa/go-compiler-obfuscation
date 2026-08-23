# Full Protection Demo

`main.go` is a single source module that can be built both as a protected
Windows executable and as a protected Linux C shared library. All sensitive
and algorithmic functions are marked with the compiler directives:

- `vmMix`: VM v4 plus constant encryption.
- `ephemeralCheck`: String v3 ephemeral decode and wipe.
- `streamCheck`: String v4 bounded byte stream.
- `leaseCheck`: String v5 lease-bound bounded byte stream.
- `encryptedInput`: native 64-bit constant encryption.

The C ABI bridge (`FullProtectVerify`) and executable launcher (`main`) are
intentionally thin: cgo ABI functions and multi-block entry functions are
outside the current native/VM directive boundary. They contain no secrets or
large protected constants. Every string, key-dependent check, and application
calculation lives in the five marked functions above, which receive hidden
names where ABI permits, encoded pclntab entries, Runtime Guard v3, randomized
layout, and hashed pclntab filenames.

`FullProtectVerify` retains its name because it is the C ABI entry exported by
the generated header. It only converts the ABI value and invokes protected
functions, so the required external symbol spelling is the only exposed bridge
metadata.

Run `misc/obf/build-full-demo.ps1` from the compiler root to generate and
verify `full-protect.exe`, `full-protect.so`, and `full-protect.h`.
