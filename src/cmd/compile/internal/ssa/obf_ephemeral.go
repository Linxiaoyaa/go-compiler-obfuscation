// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"fmt"
	"strings"
)

// obfEphemeral installs explicit wipe calls for String v3 literals. The
// directive is intentionally strict: the decoded string must stay inside the
// current function, and the decoder call must dominate every return. This
// makes the wipe point provable instead of relying on a guessed last use.
func obfEphemeral(f *Func) {
	flags := f.fe.Func().Protection
	if flags&ir.ProtectEphemeral == 0 || flags&ir.ProtectExclude != 0 {
		return
	}

	type literal struct {
		ptr, length *Value
		call        *Value
	}
	var literals []literal
	for _, b := range f.Blocks {
		for _, call := range b.Values {
			if call.Op != OpStaticLECall && call.Op != OpStaticCall {
				continue
			}
			aux, ok := call.Aux.(*AuxCall)
			if !ok || aux.Fn == nil || !strings.Contains(aux.Fn.Name, "runtime.obfStringDataV3") {
				continue
			}
			var ptr, length *Value
			for _, candidate := range b.Values {
				if candidate.Op != OpSelectN || len(candidate.Args) == 0 || candidate.Args[0] != call {
					continue
				}
				switch candidate.AuxInt {
				case 0:
					ptr = candidate
				case 1:
					length = candidate
				}
			}
			if ptr == nil || length == nil || b != f.Entry {
				protectionError(f, "ephemeral", "String v3 decoder must be in the function entry block")
				return
			}
			var stringValue *Value
			for _, candidate := range b.Values {
				if candidate.Op == OpStringMake && len(candidate.Args) == 2 && candidate.Args[0] == ptr && candidate.Args[1] == length {
					stringValue = candidate
					break
				}
			}
			if stringValue == nil {
				protectionError(f, "ephemeral", "could not find the decoded string header")
				return
			}
			if err := validateEphemeralUses(f, stringValue, ptr); err != nil {
				protectionError(f, "ephemeral", "%v", err)
				return
			}
			literals = append(literals, literal{ptr: ptr, length: length, call: call})
		}
	}
	if len(literals) == 0 {
		protectionError(f, "ephemeral", "no protected string literal was lowered")
		return
	}

	for _, b := range f.Blocks {
		if b.Kind != BlockRet || len(b.Controls) != 1 || b.Controls[0].Op != OpMakeResult {
			continue
		}
		result := b.Controls[0]
		mem := result.Args[len(result.Args)-1]
		// Make the wipe depend on all returned values. In particular, this
		// orders it after loads from the decoded string instead of merely
		// keeping the allocation reachable until an otherwise independent call.
		for _, value := range result.Args[:len(result.Args)-1] {
			mem = b.NewValue2(result.Pos, OpKeepAlive, types.TypeMem, value, mem)
		}
		for _, lit := range literals {
			mem = emitEphemeralWipe(b, lit.ptr, lit.length, mem)
		}
		result.SetArg(len(result.Args)-1, mem)
	}
}

func validateEphemeralUses(f *Func, stringValue, decodedPtr *Value) error {
	seenStrings := map[*Value]bool{stringValue: true}
	seenPtrs := map[*Value]bool{decodedPtr: true}
	stringQueue := []*Value{stringValue}
	ptrQueue := []*Value{decodedPtr}

	for len(stringQueue) > 0 {
		value := stringQueue[0]
		stringQueue = stringQueue[1:]
		for _, b := range f.Blocks {
			for _, user := range b.Values {
				for _, arg := range user.Args {
					if arg != value {
						continue
					}
					switch user.Op {
					case OpStringLen:
					case OpStringPtr:
						if !seenPtrs[user] {
							seenPtrs[user] = true
							ptrQueue = append(ptrQueue, user)
						}
					case OpCopy, OpPhi:
						if !seenStrings[user] {
							seenStrings[user] = true
							stringQueue = append(stringQueue, user)
						}
					default:
						return fmt.Errorf("decoded string escapes through %s", user.Op.String())
					}
				}
			}
		}
	}

	for len(ptrQueue) > 0 {
		value := ptrQueue[0]
		ptrQueue = ptrQueue[1:]
		for _, b := range f.Blocks {
			for _, user := range b.Values {
				for argIndex, arg := range user.Args {
					if arg != value {
						continue
					}
					if value == decodedPtr && user.Op == OpStringMake {
						continue
					}
					switch user.Op {
					case OpLoad:
					case OpOffPtr, OpAddPtr, OpPtrIndex, OpCopy, OpPhi:
						if !seenPtrs[user] {
							seenPtrs[user] = true
							ptrQueue = append(ptrQueue, user)
						}
					case OpIsNonNil, OpEqPtr, OpNeqPtr:
					default:
						return fmt.Errorf("decoded string storage escapes through %s (arg %d)", user.Op.String(), argIndex)
					}
				}
			}
		}
	}
	return nil
}

func emitEphemeralWipe(b *Block, ptr, length, mem *Value) *Value {
	f := b.Func
	pos := b.Pos
	argTypes := []*types.Type{ptr.Type, length.Type}
	aux := StaticAuxCall(f.fe.Syslook("obfStringWipeV3"), f.ABIDefault.ABIAnalyzeTypes(argTypes, nil))
	call := b.NewValue0A(pos, OpStaticLECall, aux.LateExpansionResultType(), aux)
	call.AddArgs(ptr, length, mem)
	off := f.Config.ctxt.Arch.FixedFrameSize
	for _, typ := range argTypes {
		off = types.RoundUp(off, typ.Alignment()) + typ.Size()
	}
	call.AuxInt = types.RoundUp(off, f.Config.RegSize)
	return b.NewValue1I(pos, OpSelectN, types.TypeMem, 0, call)
}
