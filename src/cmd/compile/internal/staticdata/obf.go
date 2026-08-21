// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package staticdata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
)

// ObfuscatedStringKey contains the compiler-only material needed by one
// protected literal. The four lanes are derived independently from the build,
// function, and literal domains. Decoder selects one of several runtime
// implementations so protected literals do not all converge on one entry.
type ObfuscatedStringKey struct {
	Lanes   [4]uint64
	Decoder uint8
}

const protectedFunctionFlags = ir.ProtectObfuscate | ir.ProtectEncrypt | ir.ProtectVirtualize

// ObfuscateProtectedFuncLinkname assigns a deterministic, package-independent
// linker name to a protected non-exported Go function. The source-level name
// remains intact for type checking and diagnostics; only emitted symbols and
// propagated linker references change. It returns false for ABI-sensitive or
// special entry points that must retain their conventional names.
func ObfuscateProtectedFuncLinkname(fn *ir.Func, seed string) (string, bool) {
	if fn == nil || fn.Nname == nil || fn.Protection&protectedFunctionFlags == 0 {
		return "", false
	}
	if fn.IsPackageInit() || fn.ABIWrapper() || fn.WasmExport != nil || fn.ABI != obj.ABIInternal {
		return "", false
	}
	sym := fn.Sym()
	if sym == nil || sym.Pkg == nil || sym.Linkname != "" || sym.Pkg.Path == "runtime" {
		return "", false
	}
	name := sym.Name
	if name == "main" || name == "init" || name == "TestMain" {
		return "", false
	}
	// Methods participate in wrapper generation, interface method sets, and
	// reflection metadata; keep their linker identity stable in this first
	// version. Top-level exported functions are also left alone because external
	// linkname/plugin users cannot be rewritten by this compiler alone.
	method := strings.LastIndexByte(name, '.') >= 0
	localName := name
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		localName = name[dot+1:]
	}
	if method || types.IsExported(localName) {
		return "", false
	}

	digest := hashParts(
		[]byte("go-obf-function-link-v1"),
		[]byte(seed),
		[]byte(sym.Pkg.Path),
		[]byte(name),
	)
	linkname := "obf.fn." + hex.EncodeToString(digest[:16])
	sym.Linkname = linkname
	return linkname, true
}

// ObfuscatedStringSym emits an encrypted backing symbol for a string literal
// and returns the material used by the String v2 runtime decoders. The symbol
// name is a digest rather than the ciphertext, so neither plaintext nor a
// reversible literal spelling is carried in object metadata.
func ObfuscatedStringSym(pos src.XPos, functionName, seed, text string) (*obj.LSym, ObfuscatedStringKey) {
	key := obfuscatedStringKeyV2(functionName, seed, text)
	return obfuscatedStringSym(pos, text, key, "go-obf-string-symbol-v2")
}

// ObfuscatedStringSymV3 emits ciphertext for an ephemeral protected literal.
// Its derivation and symbol domain are separate from String v2 so changing the
// lifetime policy also changes keys, ciphertext, and object identity.
func ObfuscatedStringSymV3(pos src.XPos, functionName, seed, text string) (*obj.LSym, ObfuscatedStringKey) {
	key := obfuscatedStringKeyV3(functionName, seed, text)
	return obfuscatedStringSym(pos, text, key, "go-obf-string-symbol-v3")
}

// ObfuscatedStringSymV4 emits ciphertext for a stream-only protected literal.
// String v4 never decodes the complete literal into a Go string. Its key and
// ciphertext domains are deliberately separate from v2 and v3 so a policy
// change cannot reuse a prior protected payload.
func ObfuscatedStringSymV4(pos src.XPos, functionName, seed, text string) (*obj.LSym, ObfuscatedStringKey) {
	key := obfuscatedStringKeyV4(functionName, seed, text)
	return obfuscatedStringSym(pos, text, key, "go-obf-string-symbol-v4")
}

func obfuscatedStringSym(pos src.XPos, text string, key ObfuscatedStringKey, symbolDomain string) (*obj.LSym, ObfuscatedStringKey) {
	ciphertext := make([]byte, len(text))
	for i := range ciphertext {
		ciphertext[i] = text[i] ^ obfuscatedStringMaskV2(key.Lanes, key.Decoder, i)
	}

	// Keep the symbol content-addressable, but derive its name from the
	// ciphertext and the protection domain instead of exposing either directly.
	digest := hashParts([]byte(symbolDomain), ciphertext)
	name := "go:obfstr." + hex.EncodeToString(digest[:16])
	sym := base.Ctxt.Lookup(name)
	if !sym.OnList() {
		off := dstringdata(sym, 0, string(ciphertext), pos, "obfuscated string")
		objw.Global(sym, int32(off), obj.DUPOK|obj.RODATA|obj.LOCAL)
		sym.Set(obj.AttrContentAddressable, true)
	}
	return sym, key
}

func obfuscatedStringKeyV3(functionName, seed, text string) ObfuscatedStringKey {
	root := hashParts([]byte("go-obf-string-v3/root"), []byte(seed))
	function := hashParts(root[:], []byte("function"), []byte(functionName))
	literal := hashParts(function[:], []byte("ephemeral-literal"), []byte(text))
	mask := hashParts(literal[:], []byte("ephemeral-mask"))

	var key ObfuscatedStringKey
	for i := range key.Lanes {
		off := i * 8
		key.Lanes[i] = binary.LittleEndian.Uint64(literal[off:off+8]) ^
			binary.LittleEndian.Uint64(mask[off:off+8])
	}
	key.Decoder = (literal[1] ^ literal[17]) & 3
	return key
}

func obfuscatedStringKeyV4(functionName, seed, text string) ObfuscatedStringKey {
	root := hashParts([]byte("go-obf-string-v4/root"), []byte(seed))
	function := hashParts(root[:], []byte("function"), []byte(functionName))
	literal := hashParts(function[:], []byte("stream-literal"), []byte(text))
	mask := hashParts(literal[:], []byte("stream-byte-mask"))

	var key ObfuscatedStringKey
	for i := range key.Lanes {
		off := i * 8
		key.Lanes[i] = binary.LittleEndian.Uint64(literal[off:off+8]) ^
			binary.LittleEndian.Uint64(mask[off:off+8])
	}
	key.Decoder = (literal[7] ^ literal[23]) & 3
	return key
}

func obfuscatedStringKeyV2(functionName, seed, text string) ObfuscatedStringKey {
	// Derive independent domains rather than hashing a single concatenated
	// string. Length-prefixing in hashParts also prevents delimiter ambiguity.
	root := hashParts([]byte("go-obf-string-v2/root"), []byte(seed))
	function := hashParts(root[:], []byte("function"), []byte(functionName))
	literal := hashParts(function[:], []byte("literal"), []byte(text))
	mask := hashParts(literal[:], []byte("mask"))

	var key ObfuscatedStringKey
	for i := range key.Lanes {
		off := i * 8
		key.Lanes[i] = binary.LittleEndian.Uint64(literal[off:off+8]) ^
			binary.LittleEndian.Uint64(mask[off:off+8])
	}
	key.Decoder = literal[0] & 3
	return key
}

func hashParts(parts ...[]byte) [32]byte {
	h := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.LittleEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(part)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func obfuscatedStringMaskV2(lanes [4]uint64, decoder uint8, index int) byte {
	i := uint64(index)
	a, b, c, d := lanes[0], lanes[1], lanes[2], lanes[3]
	var x uint64
	switch decoder & 3 {
	case 0:
		x = a + i*0x9e3779b97f4a7c15
		x ^= rotate64(b^i, uint(i&63))
		x += c ^ (d + i*0xd1b54a32d192ed03)
	case 1:
		x = b + i*0xd1b54a32d192ed03
		x ^= rotate64(c+i, uint((i+17)&63))
		x += d ^ (a + i*0x9e3779b97f4a7c15)
	case 2:
		x = c + i*0x94d049bb133111eb
		x ^= rotate64(d^i, uint((i+31)&63))
		x += a ^ (b + i*0xbf58476d1ce4e5b9)
	default:
		x = d + i*0xbf58476d1ce4e5b9
		x ^= rotate64(a+i, uint((i+47)&63))
		x += b ^ (c + i*0x94d049bb133111eb)
	}
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return byte(x >> uint((i&7)*8))
}

func rotate64(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return x<<n | x>>(64-n)
}
