// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"fmt"
	"strings"
)

// obfStream implements String v4 through v6. The lowering initially constructs a
// string header that points at ciphertext. Before calls are expanded, this pass
// proves that every use is a length query or a byte load and replaces each byte
// load with a runtime decoder call. No complete plaintext Go string is
// allocated or materialized by this representation.
func obfStream(f *Func) {
	flags := f.fe.Func().Protection
	if flags&(ir.ProtectStream|ir.ProtectStreamV5|ir.ProtectStreamV6) == 0 || flags&ir.ProtectExclude != 0 {
		return
	}
	directive := "stream"
	if flags&ir.ProtectStreamV6 != 0 {
		directive = "streamv6"
	} else if flags&ir.ProtectStreamV5 != 0 {
		directive = "streamv5"
	}

	graph := newStreamGraph(f)
	tokens, err := findStreamTokens(graph)
	if err != nil {
		protectionError(f, directive, "%v", err)
		return
	}
	if len(tokens) == 0 {
		protectionError(f, directive, "no protected stream literal was lowered")
		return
	}
	for _, token := range tokens {
		if err := rewriteStreamToken(f, graph, token); err != nil {
			protectionError(f, directive, "%v", err)
			return
		}
	}
}

type streamToken struct {
	call               *Value
	stringValue        *Value
	ciphertext, length *Value
	keys               [4]*Value
	lease              *Value
	ticket             *Value
	decoder            uint8
	version            int
	stringLengths      []*Value
	loads              []streamLoad
}

type streamPointer struct {
	dynamicOffset *Value
	constantOff   int64
}

type streamLoad struct {
	load    *Value
	pointer streamPointer
}

type streamUse struct {
	value    *Value
	argIndex int
}

// streamGraph is built once per function. It avoids repeatedly walking every
// SSA value while validating multiple String v4 literals or byte indexes.
type streamGraph struct {
	values []*Value
	uses   map[*Value][]streamUse
}

func newStreamGraph(f *Func) streamGraph {
	graph := streamGraph{uses: make(map[*Value][]streamUse)}
	seen := make(map[*Value]bool)
	for _, b := range f.Blocks {
		for _, value := range b.Values {
			if value != nil && !seen[value] {
				seen[value] = true
				graph.values = append(graph.values, value)
			}
		}
		for _, control := range b.Controls {
			if control != nil && !seen[control] {
				seen[control] = true
				graph.values = append(graph.values, control)
			}
		}
	}
	for _, value := range graph.values {
		for argIndex, arg := range value.Args {
			if arg != nil {
				graph.uses[arg] = append(graph.uses[arg], streamUse{value: value, argIndex: argIndex})
			}
		}
	}
	return graph
}

func findStreamTokens(graph streamGraph) ([]*streamToken, error) {
	var tokens []*streamToken
	for _, call := range graph.values {
		if !isStreamTokenCall(call) {
			continue
		}
		version, decoder, ok := streamDecoder(call)
		// The late-call form carries six ABI arguments followed by the
		// memory dependency. Keep the dependency in the graph so a token
		// cannot be detached from the surrounding memory chain.
		expectedArgs := 7
		if version >= 5 {
			expectedArgs++
		}
		if version == 6 {
			expectedArgs++
		}
		if !ok || len(call.Args) != expectedArgs || call.Args[expectedArgs-1].Type.Compare(types.TypeMem) != types.CMPeq {
			return nil, fmt.Errorf("malformed String v%d token call", version)
		}
		token := &streamToken{
			call:       call,
			ciphertext: call.Args[0],
			length:     call.Args[1],
			decoder:    decoder,
			version:    version,
		}
		copy(token.keys[:], call.Args[2:6])
		if version >= 5 {
			token.lease = call.Args[6]
		}
		if version == 6 {
			token.ticket = call.Args[7]
		}
		pointerResults := streamTokenResults(graph, call, 0)
		lengthResults := streamTokenResults(graph, call, 1)
		for pointer := range pointerResults {
			for _, use := range graph.uses[pointer] {
				candidate := use.value
				if use.argIndex != 0 || candidate.Op != OpStringMake || len(candidate.Args) != 2 || !lengthResults[candidate.Args[1]] {
					continue
				}
				if token.stringValue != nil {
					return nil, fmt.Errorf("String v%d token feeds multiple string headers", version)
				}
				token.stringValue = candidate
			}
		}
		if token.stringValue == nil {
			return nil, fmt.Errorf("could not find String v%d ciphertext header", version)
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func isStreamTokenCall(v *Value) bool {
	if v.Op != OpStaticCall && v.Op != OpStaticLECall {
		return false
	}
	aux, ok := v.Aux.(*AuxCall)
	return ok && aux.Fn != nil && (strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV4") || strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV5") || strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV6"))
}

func streamDecoder(v *Value) (int, uint8, bool) {
	aux, ok := v.Aux.(*AuxCall)
	if !ok || aux.Fn == nil || len(aux.Fn.Name) == 0 {
		return 0, 0, false
	}
	version := 0
	if strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV4") {
		version = 4
	} else if strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV5") {
		version = 5
	} else if strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV6") {
		version = 6
	} else {
		return 0, 0, false
	}
	switch aux.Fn.Name[len(aux.Fn.Name)-1] {
	case 'A':
		return version, 0, true
	case 'B':
		return version, 1, true
	case 'C':
		return version, 2, true
	case 'D':
		return version, 3, true
	default:
		return 0, 0, false
	}
}

func streamTokenResults(graph streamGraph, call *Value, index int64) map[*Value]bool {
	results := make(map[*Value]bool)
	var queue []*Value
	for _, use := range graph.uses[call] {
		value := use.value
		if value.Op == OpSelectN && use.argIndex == 0 && value.AuxInt == index {
			results[value] = true
			queue = append(queue, value)
		}
	}
	for len(queue) > 0 {
		value := queue[0]
		queue = queue[1:]
		for _, use := range graph.uses[value] {
			copy := use.value
			if use.argIndex == 0 && copy.Op == OpCopy && !results[copy] {
				results[copy] = true
				queue = append(queue, copy)
			}
		}
	}
	return results
}

func rewriteStreamToken(f *Func, graph streamGraph, token *streamToken) error {
	stringValues := map[*Value]bool{token.stringValue: true}
	stringQueue := []*Value{token.stringValue}
	pointerValues := make(map[*Value]streamPointer)
	pointerQueue := make([]*Value, 0, 4)

	for len(stringQueue) > 0 {
		value := stringQueue[0]
		stringQueue = stringQueue[1:]
		for _, use := range graph.uses[value] {
			user, argIndex := use.value, use.argIndex
			switch user.Op {
			case OpStringLen:
				token.stringLengths = append(token.stringLengths, user)
			case OpStringPtr:
				if argIndex != 0 {
					return fmt.Errorf("malformed String v%d pointer use", token.version)
				}
				if _, exists := pointerValues[user]; !exists {
					pointerValues[user] = streamPointer{}
					pointerQueue = append(pointerQueue, user)
				}
			case OpCopy:
				if argIndex != 0 {
					return fmt.Errorf("malformed String v%d copy", token.version)
				}
				if !stringValues[user] {
					stringValues[user] = true
					stringQueue = append(stringQueue, user)
				}
			default:
				return fmt.Errorf("ciphertext string escapes through %s (arg %d)", user.Op.String(), argIndex)
			}
		}
	}

	for len(pointerQueue) > 0 {
		pointer := pointerQueue[0]
		pointerQueue = pointerQueue[1:]
		state := pointerValues[pointer]
		for _, use := range graph.uses[pointer] {
			user, argIndex := use.value, use.argIndex
			switch user.Op {
			case OpOffPtr:
				if argIndex != 0 {
					return fmt.Errorf("malformed String v%d offset pointer", token.version)
				}
				next := state
				next.constantOff += user.AuxInt
				if err := addStreamPointer(pointerValues, &pointerQueue, user, next); err != nil {
					return err
				}
			case OpAddPtr:
				if argIndex != 0 || len(user.Args) != 2 || user.Args[1].Type.Compare(f.Config.Types.Int) != types.CMPeq {
					return fmt.Errorf("String v%d index must be an int", token.version)
				}
				if state.dynamicOffset != nil {
					return fmt.Errorf("String v%d pointer has multiple dynamic indexes", token.version)
				}
				next := state
				next.dynamicOffset = user.Args[1]
				if err := addStreamPointer(pointerValues, &pointerQueue, user, next); err != nil {
					return err
				}
			case OpCopy:
				if argIndex != 0 {
					return fmt.Errorf("malformed String v%d pointer copy", token.version)
				}
				if err := addStreamPointer(pointerValues, &pointerQueue, user, state); err != nil {
					return err
				}
			case OpLoad:
				if argIndex != 0 || user.Type.Compare(f.Config.Types.UInt8) != types.CMPeq || len(user.Args) != 2 {
					return fmt.Errorf("String v%d only permits byte loads", token.version)
				}
				token.loads = append(token.loads, streamLoad{load: user, pointer: state})
			default:
				return fmt.Errorf("ciphertext storage escapes through %s (arg %d)", user.Op.String(), argIndex)
			}
		}
	}

	if len(token.loads) == 0 {
		return fmt.Errorf("String v%d literal is not consumed by a byte index", token.version)
	}
	for _, length := range token.stringLengths {
		length.copyOf(token.length)
	}
	for _, load := range token.loads {
		index := streamIndexValue(f, load.load.Block, load.load.Pos, load.pointer)
		decoded := emitStreamByteCall(load.load.Block, load.load.Pos, token, index, load.load.Args[1])
		load.load.copyOf(decoded)
	}
	return nil
}

func addStreamPointer(values map[*Value]streamPointer, queue *[]*Value, value *Value, state streamPointer) error {
	if prior, exists := values[value]; exists {
		if prior.constantOff != state.constantOff || prior.dynamicOffset != state.dynamicOffset {
			return fmt.Errorf("String v4 pointer merges incompatible offsets")
		}
		return nil
	}
	values[value] = state
	*queue = append(*queue, value)
	return nil
}

func streamIndexValue(f *Func, b *Block, pos src.XPos, state streamPointer) *Value {
	if state.dynamicOffset == nil {
		return streamIntConst(f, state.constantOff)
	}
	if state.constantOff == 0 {
		return state.dynamicOffset
	}
	constant := streamIntConst(f, state.constantOff)
	if f.Config.PtrSize == 8 {
		return b.NewValue2(pos, OpAdd64, f.Config.Types.Int, state.dynamicOffset, constant)
	}
	return b.NewValue2(pos, OpAdd32, f.Config.Types.Int, state.dynamicOffset, constant)
}

func streamIntConst(f *Func, value int64) *Value {
	if f.Config.PtrSize == 8 {
		return f.ConstInt64(f.Config.Types.Int, value)
	}
	return f.ConstInt32(f.Config.Types.Int, int32(value))
}

func emitStreamByteCall(b *Block, pos src.XPos, token *streamToken, index, mem *Value) *Value {
	f := b.Func
	argTypes := []*types.Type{
		token.ciphertext.Type,
		token.length.Type,
		index.Type,
		f.Config.Types.UInt64,
		f.Config.Types.UInt64,
		f.Config.Types.UInt64,
		f.Config.Types.UInt64,
	}
	if token.version >= 5 {
		argTypes = append(argTypes, f.Config.Types.UInt64)
	}
	if token.version == 6 {
		argTypes = append(argTypes, f.Config.Types.UInt64)
	}
	aux := StaticAuxCall(f.fe.Syslook(streamByteRuntimeName(token.version, token.decoder)), f.ABIDefault.ABIAnalyzeTypes(argTypes, []*types.Type{f.Config.Types.UInt8}))
	call := b.NewValue0A(pos, OpStaticLECall, aux.LateExpansionResultType(), aux)
	call.AddArgs(token.ciphertext, token.length, index, token.keys[0], token.keys[1], token.keys[2], token.keys[3])
	if token.version >= 5 {
		call.AddArg(token.lease)
	}
	if token.version == 6 {
		call.AddArg(token.ticket)
	}
	call.AddArg(mem)
	off := f.Config.ctxt.Arch.FixedFrameSize
	for _, typ := range argTypes {
		off = types.RoundUp(off, typ.Alignment()) + typ.Size()
	}
	off = types.RoundUp(off, f.Config.RegSize)
	off = types.RoundUp(off, f.Config.Types.UInt8.Alignment()) + f.Config.Types.UInt8.Size()
	call.AuxInt = types.RoundUp(off, f.Config.PtrSize)
	return b.NewValue1I(pos, OpSelectN, f.Config.Types.UInt8, 0, call)
}

func streamByteRuntimeName(version int, decoder uint8) string {
	prefix := "obfStringByteV4"
	if version == 5 {
		prefix = "obfStringByteV5"
	} else if version == 6 {
		prefix = "obfStringByteV6"
	}
	switch decoder & 3 {
	case 0:
		return prefix + "A"
	case 1:
		return prefix + "B"
	case 2:
		return prefix + "C"
	default:
		return prefix + "D"
	}
}
