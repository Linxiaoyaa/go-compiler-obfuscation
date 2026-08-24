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
	Lease   uint64
	Ticket  uint64
}

const protectedFunctionFlags = ir.ProtectObfuscate | ir.ProtectEncrypt | ir.ProtectVirtualize

// ObfuscateProtectedFuncLinkname assigns a deterministic, package-independent
// linker name to a protected non-exported Go function. The source-level name
// remains intact for type checking and diagnostics; only emitted symbols and
// propagated linker references change. It returns false for ABI-sensitive or
// special entry points that must retain their conventional names.
func ObfuscateProtectedFuncLinkname(fn *ir.Func, seed string) (string, bool) {
	if fn == nil || fn.Nname == nil || !hasProtectedFunctionOwner(fn) {
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
	// reflection metadata; keep their linker identity stable. Compiler-created
	// closures and defer wrappers also contain dots, but are local implementation
	// details and must inherit the protected owner's hashed symbol identity.
	closure := fn.ClosureParent != nil
	method := !closure && strings.LastIndexByte(name, '.') >= 0
	localName := name
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		localName = name[dot+1:]
	}
	if method || (!closure && types.IsExported(localName)) {
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

// hasProtectedFunctionOwner follows compiler-generated closure ownership so a
// protected function cannot leak its source name through .funcN, .gowrapN, or
// .deferwrapN symbols. These helpers have no externally callable identity.
func hasProtectedFunctionOwner(fn *ir.Func) bool {
	for current := fn; current != nil; current = current.ClosureParent {
		if current.Protection&protectedFunctionFlags != 0 {
			return true
		}
	}
	return false
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

// ObfuscatedStringSymV5 emits ciphertext for a lease-bound stream-only
// literal. Its byte mask and the lease word use a separate domain from every
// earlier string mode, so v5 cannot reuse a v4 token or decoder schedule.
func ObfuscatedStringSymV5(pos src.XPos, functionName, seed, text string) (*obj.LSym, ObfuscatedStringKey) {
	key := obfuscatedStringKeyV5(functionName, seed, text)
	return obfuscatedStringSym(pos, text, key, "go-obf-string-symbol-v5")
}

// ObfuscatedStringSymV6 emits ciphertext for a capability-bound stream-only
// literal. In addition to the v5 lease, v6 carries an independently derived
// ticket through the token and each byte decode so copied call operands cannot
// satisfy a decoder from a different literal domain.
func ObfuscatedStringSymV6(pos src.XPos, functionName, seed, text string) (*obj.LSym, ObfuscatedStringKey) {
	key := obfuscatedStringKeyV6(functionName, seed, text)
	return obfuscatedStringSym(pos, text, key, "go-obf-string-symbol-v6")
}

func obfuscatedStringSym(pos src.XPos, text string, key ObfuscatedStringKey, symbolDomain string) (*obj.LSym, ObfuscatedStringKey) {
	ciphertext := make([]byte, len(text))
	for i := range ciphertext {
		mask := obfuscatedStringMaskV2(key.Lanes, key.Decoder, i)
		if key.Ticket != 0 {
			mask = obfuscatedStringMaskV6(key.Lanes, key.Lease, key.Ticket, key.Decoder, i)
		} else if key.Lease != 0 {
			mask = obfuscatedStringMaskV5(key.Lanes, key.Lease, key.Decoder, i)
		}
		ciphertext[i] = text[i] ^ mask
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

func obfuscatedStringKeyV5(functionName, seed, text string) ObfuscatedStringKey {
	root := hashParts([]byte("go-obf-string-v5/root"), []byte(seed))
	function := hashParts(root[:], []byte("function"), []byte(functionName))
	literal := hashParts(function[:], []byte("lease-stream-literal"), []byte(text))
	mask := hashParts(literal[:], []byte("lease-stream-mask"))
	lease := hashParts(mask[:], []byte("lease"))

	var key ObfuscatedStringKey
	for i := range key.Lanes {
		off := i * 8
		key.Lanes[i] = binary.LittleEndian.Uint64(literal[off:off+8]) ^
			binary.LittleEndian.Uint64(mask[off:off+8])
	}
	key.Lease = binary.LittleEndian.Uint64(lease[:8]) ^ binary.LittleEndian.Uint64(mask[24:32])
	if key.Lease == 0 {
		key.Lease = 0x6a09e667f3bcc909
	}
	key.Decoder = (literal[5] ^ literal[29] ^ lease[13]) & 3
	return key
}

func obfuscatedStringKeyV6(functionName, seed, text string) ObfuscatedStringKey {
	root := hashParts([]byte("go-obf-string-v6/root"), []byte(seed))
	function := hashParts(root[:], []byte("function"), []byte(functionName))
	literal := hashParts(function[:], []byte("ticket-stream-literal"), []byte(text))
	mask := hashParts(literal[:], []byte("ticket-stream-mask"))
	lease := hashParts(mask[:], []byte("lease"), function[:])
	ticket := hashParts(literal[:], []byte("ticket"), root[:])

	var key ObfuscatedStringKey
	for i := range key.Lanes {
		off := i * 8
		key.Lanes[i] = binary.LittleEndian.Uint64(literal[off:off+8]) ^
			binary.LittleEndian.Uint64(mask[off:off+8])
	}
	key.Lease = binary.LittleEndian.Uint64(lease[:8]) ^ binary.LittleEndian.Uint64(mask[24:32])
	if key.Lease == 0 {
		key.Lease = 0x6a09e667f3bcc909
	}
	key.Ticket = binary.LittleEndian.Uint64(ticket[:8]) ^ binary.LittleEndian.Uint64(lease[16:24])
	if key.Ticket == 0 {
		key.Ticket = 0xbb67ae8584caa73b
	}
	key.Decoder = (literal[3] ^ literal[21] ^ lease[11] ^ ticket[19]) & 3
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

func obfuscatedStringMaskV5(lanes [4]uint64, lease uint64, decoder uint8, index int) byte {
	i := uint64(index)
	x := lease ^ lanes[(uint64(decoder)+i)&3]
	x += i*0xd6e8feb86659fd93 + 0xa4093822299f31d0
	x ^= rotate64(lanes[(uint64(decoder)+i+1)&3]^lease, uint((i+uint64(decoder)*11)&63))
	x ^= x >> 29
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return obfuscatedStringMaskV2(lanes, decoder, index) ^ byte(x>>uint((i&7)*8))
}

func obfuscatedStringMaskV6(lanes [4]uint64, lease, ticket uint64, decoder uint8, index int) byte {
	i := uint64(index)
	x := ticket ^ rotate64(lease, uint((i+uint64(decoder)*13)&63))
	x += lanes[(i+uint64(decoder)*3)&3] + i*0x9e3779b185ebca87
	x ^= rotate64(lanes[(i+uint64(decoder)+2)&3]^ticket, uint((i+29)&63))
	x ^= x >> 27
	x *= 0xd6e8feb86659fd93
	x ^= x >> 33
	return obfuscatedStringMaskV5(lanes, lease, decoder, index) ^ byte(x>>uint((i&7)*8))
}

func rotate64(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return x<<n | x>>(64-n)
}
