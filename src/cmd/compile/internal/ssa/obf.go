// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
)

const protectionPragmas = ir.ProtectObfuscate | ir.ProtectEncrypt | ir.ProtectVirtualize | ir.ProtectEphemeral | ir.ProtectStream | ir.ProtectStreamV5

type vmOpcode uint8

const (
	vmPushArg vmOpcode = iota
	vmPushConst
	vmAdd
	vmSub
	vmMul
	vmAnd
	vmOr
	vmXor
	vmLsh
	vmRsh
	vmNeg
	vmCom
	vmReturn
)

func (op vmOpcode) String() string {
	switch op {
	case vmPushArg:
		return "push-arg"
	case vmPushConst:
		return "push-const"
	case vmAdd:
		return "add"
	case vmSub:
		return "sub"
	case vmMul:
		return "mul"
	case vmAnd:
		return "and"
	case vmOr:
		return "or"
	case vmXor:
		return "xor"
	case vmLsh:
		return "lsh"
	case vmRsh:
		return "rsh"
	case vmNeg:
		return "neg"
	case vmCom:
		return "com"
	case vmReturn:
		return "return"
	default:
		return "unknown"
	}
}

type vmInstruction struct {
	op    vmOpcode
	arg   *Value
	imm   uint64
	depth int
	pos   src.XPos
}

type protectionRNG struct {
	state uint64
}

func newProtectionRNG(f *Func) *protectionRNG {
	return newProtectionRNGDomain(f, "")
}

func newProtectionRNGDomain(f *Func, domain string) *protectionRNG {
	h := fnv.New64a()
	_, _ = h.Write([]byte(base.Debug.ObfSeed))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(protectionFunctionName(f)))
	if domain != "" {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(domain))
	}
	seed := h.Sum64()
	if seed == 0 {
		seed = 0x6a09e667f3bcc909
	}
	return &protectionRNG{state: seed}
}

func (r *protectionRNG) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func protectionFunctionName(f *Func) string {
	fn := f.fe.Func()
	if fn != nil {
		if sym := fn.Sym(); sym != nil && sym.Pkg != nil && sym.Pkg.Path != "" {
			return sym.Pkg.Path + "." + f.Name
		}
	}
	return f.Name
}

func protectionFlagsString(flags ir.ProtectionFlag) string {
	var names []string
	if flags&ir.ProtectObfuscate != 0 {
		names = append(names, "obf")
	}
	if flags&ir.ProtectEncrypt != 0 {
		names = append(names, "encrypt")
	}
	if flags&ir.ProtectVirtualize != 0 {
		names = append(names, "vm")
	}
	if flags&ir.ProtectEphemeral != 0 {
		names = append(names, "ephemeral")
	}
	if flags&ir.ProtectStream != 0 {
		names = append(names, "stream")
	}
	if flags&ir.ProtectStreamV5 != 0 {
		names = append(names, "streamv5")
	}
	if flags&ir.ProtectExclude != 0 {
		names = append(names, "noprotect")
	}
	return strings.Join(names, ",")
}

func reportProtection(f *Func, flags ir.ProtectionFlag, applied string) {
	if base.Debug.ObfReport == 0 {
		return
	}
	if fn := f.fe.Func(); fn != nil && fn.Sym() != nil && strings.HasPrefix(fn.Sym().Linkname, "obf.fn.") {
		if applied != "" {
			applied += " "
		}
		applied += "name=hash-v1"
	}
	fmt.Fprintf(os.Stderr, "OBFREPORT function=%q requested=%q applied=%q\n",
		protectionFunctionName(f), protectionFlagsString(flags), applied)
}

func protectionError(f *Func, directive, format string, args ...any) {
	name := protectionFunctionName(f)
	base.ErrorfAt(f.fe.Func().Pos(), 0, "//go:%s on %s: %s", directive, name, fmt.Sprintf(format, args...))
}

func obfVirtualize(f *Func) {
	flags := f.fe.Func().Protection
	if flags&ir.ProtectExclude != 0 || flags&ir.ProtectVirtualize == 0 {
		return
	}

	beforeBlocks, beforeValues := protectionShape(f)
	program, err := buildVM2Program(f)
	if err != nil {
		protectionError(f, "vm", "%v", err)
		return
	}
	vm3, err := buildVM3Program(program, newProtectionRNGDomain(f, "vm3-layout"))
	if err != nil {
		protectionError(f, "vm", "%v", err)
		return
	}
	budget := base.Debug.ObfV4Budget
	if budget <= 0 {
		budget = 2048
	}
	aliases := len(vm3.units) / 4
	if aliases < 1 && len(vm3.units) > 1 {
		aliases = 1
	}
	if aliases > budget/32 {
		aliases = budget / 32
	}
	if aliases < 0 {
		aliases = 0
	}
	if err := installVM4Program(f, vm3, flags&ir.ProtectEncrypt != 0, aliases, budget); err != nil {
		protectionError(f, "vm", "%v", err)
		return
	}
	runtimeCheck, err := installRuntimeGuard(f)
	if err != nil {
		protectionError(f, "runtimecheck", "%v", err)
		return
	}
	afterBlocks, afterValues := protectionShape(f)

	applied := fmt.Sprintf("vm=register-threaded-v4 instructions=%d states=%d fused=%d terminal-fused=%d registers=%d source-blocks=%d branches=%d buckets=%d checks=%d decoys=%d aliases=%d budget=%d cfg-blocks=%d->%d cfg-values=%d->%d",
		len(program.instructions), len(vm3.units), vm3.fused, vm3.terminalFused, len(program.registers), len(program.blocks), program.branches,
		vm3.buckets, vm3.checks, vm3.decoys, vm3.aliases, budget, beforeBlocks, afterBlocks, beforeValues, afterValues)
	if flags&ir.ProtectEncrypt != 0 {
		applied += " encrypt=const64-state-v3"
	}
	applied += " dispatch=bucketed-islands-v1"
	if flags&ir.ProtectObfuscate != 0 {
		applied += " obf=vm-dispatch-v3"
	}
	if runtimeCheck {
		runtimeMode := "entry-v2"
		if base.Debug.ObfRuntimeCheck >= 3 {
			runtimeMode = "entry-v3"
		}
		applied += " runtime=" + runtimeMode
	}
	reportProtection(f, flags, applied)
}

func protectionShape(f *Func) (blocks, values int) {
	blocks = len(f.Blocks)
	for _, b := range f.Blocks {
		values += len(b.Values)
	}
	return blocks, values
}

func obfHarden(f *Func) {
	flags := f.fe.Func().Protection
	if flags&ir.ProtectExclude != 0 {
		reportProtection(f, flags, "excluded")
		return
	}
	if flags&protectionPragmas == 0 || flags&ir.ProtectVirtualize != 0 {
		return
	}

	var applied []string
	rng := newProtectionRNG(f)
	if flags&ir.ProtectEncrypt != 0 {
		stringProtected := hasObfuscatedStringCall(f)
		excluded := obfuscatedStringKeyConstants(f)
		if hasUint64Constants(f, excluded) || !stringProtected {
			n, err := encodeUint64Constants(f, rng)
			if err != nil {
				n, generalErr := encodeGeneralUint64Constants(f, rng)
				if generalErr != nil {
					protectionError(f, "encrypt", "%v; general fallback: %v", err, generalErr)
					return
				}
				applied = append(applied, fmt.Sprintf("encrypt=const64-general-v2(%d)", n))
			} else {
				applied = append(applied, fmt.Sprintf("encrypt=const64-v1(%d)", n))
			}
		}
		if stringProtected {
			if flags&ir.ProtectStreamV5 != 0 {
				applied = append(applied, "encrypt=str-runtime-v5-lease")
			} else if flags&ir.ProtectStream != 0 {
				applied = append(applied, "encrypt=str-runtime-v4-stream")
			} else if flags&ir.ProtectEphemeral != 0 {
				applied = append(applied, "encrypt=str-runtime-v3-ephemeral")
			} else {
				applied = append(applied, "encrypt=str-runtime-v2")
			}
		}
	}
	if flags&ir.ProtectObfuscate != 0 {
		coverage, err := insertNativeOpaqueDispatch(f, rng)
		if err != nil {
			protectionError(f, "obf", "%v", err)
			return
		}
		applied = append(applied, coverage.report())
	}
	if runtimeCheck, err := installRuntimeGuard(f); err != nil {
		protectionError(f, "runtimecheck", "%v", err)
		return
	} else if runtimeCheck {
		runtimeMode := "entry-v2"
		if base.Debug.ObfRuntimeCheck >= 3 {
			runtimeMode = "entry-v3"
		}
		applied = append(applied, "runtime="+runtimeMode)
	}
	reportProtection(f, flags, strings.Join(applied, " "))
}

// installRuntimeGuard emits a memory-ordered v2 entry call after the protection
// transforms have settled. It binds function-local data to the linker-patched
// bootstrap seal, entry key, and pclntab magic without embedding the build seed
// in the executable.
func installRuntimeGuard(f *Func) (bool, error) {
	if base.Debug.ObfRuntimeCheck == 0 {
		return false, nil
	}
	if base.Debug.ObfRuntimeCheck >= 3 {
		return installRuntimeGuardV3(f)
	}
	if base.Debug.ObfSeed == "" {
		return false, fmt.Errorf("runtime checks require a protection seed")
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpStaticCall && v.Op != OpStaticLECall {
				continue
			}
			aux, ok := v.Aux.(*AuxCall)
			if ok && aux.Fn != nil && (strings.Contains(aux.Fn.Name, "runtime.obfRuntimeGuardV1") || strings.Contains(aux.Fn.Name, "runtime.obfRuntimeGuardV2") || strings.Contains(aux.Fn.Name, "runtime.obfRuntimeGuardV3")) {
				return false, nil
			}
		}
	}

	entry := f.Entry
	var initMem *Value
	for _, v := range entry.Values {
		if v.Op == OpInitMem {
			initMem = v
			break
		}
	}
	if initMem == nil {
		return false, fmt.Errorf("could not find entry memory")
	}

	tag, seal, bootstrap := base.ObfRuntimeGuardV2Values(base.Debug.ObfSeed, protectionFunctionName(f))
	rng := newProtectionRNGDomain(f, "runtime-guard")
	sp := entry.NewValue0(entry.Pos, OpSP, f.Config.Types.Uintptr)
	source := entry.NewValue2(entry.Pos, OpConvert, f.Config.Types.UInt64, sp, initMem)
	zero := opaqueZero64(entry, source)
	tagValue := runtimeGuardConstant(entry, entry.Pos, tag, rng, zero)
	sealValue := runtimeGuardConstant(entry, entry.Pos, seal, rng, zero)
	bootstrapValue := runtimeGuardConstant(entry, entry.Pos, bootstrap, rng, zero)
	argTypes := []*types.Type{f.Config.Types.UInt64, f.Config.Types.UInt64, f.Config.Types.UInt64}
	aux := StaticAuxCall(f.fe.Syslook("obfRuntimeGuardV2"), f.ABIDefault.ABIAnalyzeTypes(argTypes, nil))
	call := entry.NewValue0A(entry.Pos, OpStaticCall, types.TypeResultMem, aux)
	call.AddArgs(tagValue, sealValue, bootstrapValue, initMem)
	call.AuxInt = aux.ArgWidth()
	guardMem := entry.NewValue1I(entry.Pos, OpSelectN, types.TypeMem, 0, call)

	// Every existing memory chain starts at initMem. Re-rooting direct users on
	// the guard result makes the check execute before a protected function can
	// perform a load, store, call, or return.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v == source || v == call || v == guardMem {
				continue
			}
			for i, arg := range v.Args {
				if arg == initMem {
					v.SetArg(i, guardMem)
				}
			}
		}
	}
	return true, nil
}

// installRuntimeGuardV3 emits the v3 entry gate. It adds independent image
// lanes and a target-platform binding to the v2 function seal while retaining
// the same memory-root ordering guarantee.
func installRuntimeGuardV3(f *Func) (bool, error) {
	if base.Debug.ObfSeed == "" {
		return false, fmt.Errorf("runtime checks require a protection seed")
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpStaticCall && v.Op != OpStaticLECall {
				continue
			}
			aux, ok := v.Aux.(*AuxCall)
			if ok && aux.Fn != nil && strings.Contains(aux.Fn.Name, "runtime.obfRuntimeGuardV3") {
				return false, nil
			}
		}
	}

	entry := f.Entry
	var initMem *Value
	for _, v := range entry.Values {
		if v.Op == OpInitMem {
			initMem = v
			break
		}
	}
	if initMem == nil {
		return false, fmt.Errorf("could not find entry memory")
	}

	tag, seal, bootstrap, imageLo, imageHi, platform := base.ObfRuntimeGuardV3Values(base.Debug.ObfSeed, protectionFunctionName(f))
	rng := newProtectionRNGDomain(f, "runtime-guard-v3")
	sp := entry.NewValue0(entry.Pos, OpSP, f.Config.Types.Uintptr)
	source := entry.NewValue2(entry.Pos, OpConvert, f.Config.Types.UInt64, sp, initMem)
	zero := opaqueZero64(entry, source)
	values := [...]uint64{tag, seal, bootstrap, imageLo, imageHi, platform}
	args := make([]*Value, len(values))
	for i, value := range values {
		args[i] = runtimeGuardConstant(entry, entry.Pos, value, rng, zero)
	}
	argTypes := make([]*types.Type, len(args))
	for i := range argTypes {
		argTypes[i] = f.Config.Types.UInt64
	}
	aux := StaticAuxCall(f.fe.Syslook("obfRuntimeGuardV3"), f.ABIDefault.ABIAnalyzeTypes(argTypes, nil))
	call := entry.NewValue0A(entry.Pos, OpStaticCall, types.TypeResultMem, aux)
	call.AddArgs(args...)
	call.AddArg(initMem)
	call.AuxInt = aux.ArgWidth()
	guardMem := entry.NewValue1I(entry.Pos, OpSelectN, types.TypeMem, 0, call)

	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v == source || v == call || v == guardMem {
				continue
			}
			for i, arg := range v.Args {
				if arg == initMem {
					v.SetArg(i, guardMem)
				}
			}
		}
	}
	return true, nil
}

func runtimeGuardConstant(b *Block, pos src.XPos, value uint64, rng *protectionRNG, zero *Value) *Value {
	mask := rng.next()
	if mask == 0 {
		mask = 0x6a09e667f3bcc909
	}
	t := b.Func.Config.Types.UInt64
	encoded := b.NewValue0I(pos, OpConst64, t, int64(value^mask))
	key := b.NewValue0I(pos, OpConst64, t, int64(mask))
	dynamicKey := b.NewValue2(pos, OpXor64, t, key, zero)
	return b.NewValue2(pos, OpXor64, t, encoded, dynamicKey)
}

// hasObfuscatedStringCall recognizes the call emitted by ssagen for protected
// literals. It is intentionally checked after expand-calls, but accepts the
// late form as well so SSA dumps and future pass reordering remain diagnostic.
func hasObfuscatedStringCall(f *Func) bool {
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpStaticCall && v.Op != OpStaticLECall {
				continue
			}
			aux, ok := v.Aux.(*AuxCall)
			if ok && aux.Fn != nil && (strings.Contains(aux.Fn.Name, "runtime.obfStringDataV2") || strings.Contains(aux.Fn.Name, "runtime.obfStringDataV3") || strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV4") || strings.Contains(aux.Fn.Name, "runtime.obfStringByteV4") || strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV5") || strings.Contains(aux.Fn.Name, "runtime.obfStringByteV5")) {
				return true
			}
		}
	}
	return false
}

// encodeUint64Constants operates on entry-block constants. Keeping the same
// boundary here lets us exclude the call-specific key value from the v1
// arithmetic eligibility check without weakening checks for other constants.
func obfuscatedStringKeyConstants(f *Func) map[*Value]bool {
	keys := make(map[*Value]bool)
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpStaticCall && v.Op != OpStaticLECall {
				continue
			}
			aux, ok := v.Aux.(*AuxCall)
			if !ok || aux.Fn == nil || (!strings.Contains(aux.Fn.Name, "runtime.obfStringDataV2") && !strings.Contains(aux.Fn.Name, "runtime.obfStringDataV3") && !strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV4") && !strings.Contains(aux.Fn.Name, "runtime.obfStringByteV4") && !strings.Contains(aux.Fn.Name, "runtime.obfStringTokenV5") && !strings.Contains(aux.Fn.Name, "runtime.obfStringByteV5")) {
				continue
			}
			for _, arg := range v.Args {
				if arg.Op == OpConst64 && arg.Type.Compare(f.Config.Types.UInt64) == types.CMPeq {
					keys[arg] = true
				}
			}
		}
	}
	return keys
}

// hasUint64Constants reports live uint64 constants in every reachable block.
// String decode keys are excluded because they are already protected by the
// runtime string path and may be located outside the entry block.
func hasUint64Constants(f *Func, excluded map[*Value]bool) bool {
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpConst64 && v.Type.Compare(f.Config.Types.UInt64) == types.CMPeq && v.Uses != 0 && !excluded[v] {
				return true
			}
		}
	}
	return false
}

func pureUint64Return(f *Func) (*Block, *Value, *Value, error) {
	if len(f.Blocks) != 1 {
		return nil, nil, nil, fmt.Errorf("v1 requires exactly one SSA basic block; got %d", len(f.Blocks))
	}
	b := f.Blocks[0]
	if b != f.Entry || b.Kind != BlockRet || b.NumControls() != 1 {
		return nil, nil, nil, fmt.Errorf("v1 requires a single return block")
	}
	result := b.Controls[0]
	if result.Op != OpMakeResult || len(result.Args) != 2 {
		return nil, nil, nil, fmt.Errorf("v1 requires exactly one return value")
	}
	root := result.Args[0]
	if root.Type.Compare(f.Config.Types.UInt64) != types.CMPeq {
		return nil, nil, nil, fmt.Errorf("v1 requires a uint64 return value; got %v", root.Type)
	}
	if result.Args[1].Op != OpInitMem {
		return nil, nil, nil, fmt.Errorf("v1 requires a pure function without memory side effects")
	}
	return b, result, root, nil
}

func buildVMProgram(f *Func) ([]vmInstruction, int, error) {
	_, _, root, err := pureUint64Return(f)
	if err != nil {
		return nil, 0, err
	}

	var program []vmInstruction
	depth := 0
	maxStack := 0
	visiting := make(map[*Value]bool)
	var emit func(*Value) error
	emit = func(v *Value) error {
		if len(program) > 128 {
			return fmt.Errorf("v1 instruction limit exceeded")
		}
		if visiting[v] {
			return fmt.Errorf("cyclic value graph at %v", v)
		}
		visiting[v] = true
		defer delete(visiting, v)

		if v.Type.Compare(f.Config.Types.UInt64) != types.CMPeq {
			return fmt.Errorf("unsupported value type %v at %v", v.Type, v)
		}
		switch v.Op {
		case OpCopy:
			return emit(v.Args[0])
		case OpArg, OpArgIntReg:
			program = append(program, vmInstruction{op: vmPushArg, arg: v, depth: depth, pos: v.Pos})
			depth++
		case OpConst64:
			program = append(program, vmInstruction{op: vmPushConst, imm: uint64(v.AuxInt), depth: depth, pos: v.Pos})
			depth++
		case OpNeg64, OpCom64:
			if len(v.Args) != 1 {
				return fmt.Errorf("malformed unary operation %v", v.Op)
			}
			if err := emit(v.Args[0]); err != nil {
				return err
			}
			op := vmNeg
			if v.Op == OpCom64 {
				op = vmCom
			}
			program = append(program, vmInstruction{op: op, depth: depth, pos: v.Pos})
		case OpAdd64, OpSub64, OpMul64, OpAnd64, OpOr64, OpXor64, OpLsh64x64, OpRsh64Ux64:
			if len(v.Args) != 2 {
				return fmt.Errorf("malformed binary operation %v", v.Op)
			}
			if err := emit(v.Args[0]); err != nil {
				return err
			}
			if err := emit(v.Args[1]); err != nil {
				return err
			}
			op := vmAdd
			switch v.Op {
			case OpSub64:
				op = vmSub
			case OpMul64:
				op = vmMul
			case OpAnd64:
				op = vmAnd
			case OpOr64:
				op = vmOr
			case OpXor64:
				op = vmXor
			case OpLsh64x64:
				op = vmLsh
			case OpRsh64Ux64:
				op = vmRsh
			}
			program = append(program, vmInstruction{op: op, depth: depth, pos: v.Pos})
			depth--
		default:
			return fmt.Errorf("unsupported SSA operation %v", v.Op)
		}
		if depth > maxStack {
			maxStack = depth
		}
		return nil
	}

	if err := emit(root); err != nil {
		return nil, 0, err
	}
	if depth != 1 {
		return nil, 0, fmt.Errorf("invalid VM stack depth %d", depth)
	}
	program = append(program, vmInstruction{op: vmReturn, depth: depth, pos: root.Pos})
	return program, maxStack, nil
}

func installVMProgram(f *Func, program []vmInstruction, maxStack int, encrypt bool) error {
	entry, makeResult, _, err := pureUint64Return(f)
	if err != nil {
		return err
	}
	if len(program) < 2 || program[len(program)-1].op != vmReturn || maxStack < 1 {
		return fmt.Errorf("invalid VM program")
	}

	rng := newProtectionRNG(f)
	states := make([]uint64, len(program))
	seen := make(map[uint64]bool)
	for i := range states {
		for {
			state := rng.next()
			if state != 0 && !seen[state] {
				states[i] = state
				seen[state] = true
				break
			}
		}
	}

	resultIndex := -1
	for i, v := range entry.Values {
		if v == makeResult {
			resultIndex = i
			break
		}
	}
	if resultIndex < 0 {
		return fmt.Errorf("return value is not owned by the entry block")
	}

	dispatch := f.NewBlock(BlockPlain)
	checks := make([]*Block, len(program))
	handlers := make([]*Block, len(program))
	for i := range program {
		checks[i] = f.NewBlock(BlockIf)
		handlers[i] = f.NewBlock(BlockPlain)
		checks[i].Pos = program[i].pos
		handlers[i].Pos = program[i].pos
	}
	invalid := f.NewBlock(BlockPlain)
	ret := f.NewBlock(BlockRet)
	dispatch.Pos = entry.Pos
	invalid.Pos = entry.Pos
	ret.Pos = entry.Pos

	makeResult.moveTo(ret, resultIndex)
	entry.Reset(BlockPlain)
	entry.Likely = BranchUnknown
	entry.AddEdgeTo(dispatch)
	dispatch.AddEdgeTo(checks[0])
	for i := range program {
		checks[i].AddEdgeTo(handlers[i])
		if i+1 < len(program) {
			checks[i].AddEdgeTo(checks[i+1])
		} else {
			checks[i].AddEdgeTo(invalid)
		}
		if program[i].op == vmReturn {
			handlers[i].AddEdgeTo(ret)
		} else {
			handlers[i].AddEdgeTo(dispatch)
		}
	}
	invalid.AddEdgeTo(handlers[len(handlers)-1])

	uint64Type := f.Config.Types.UInt64
	initialPC := entry.NewValue0I(entry.Pos, OpConst64, uint64Type, int64(states[0]))
	zero := entry.NewValue0I(entry.Pos, OpConst64, uint64Type, 0)
	pc := dispatch.NewValue0(entry.Pos, OpPhi, uint64Type)
	pc.AddArg(initialPC)
	registers := make([]*Value, maxStack)
	for i := range registers {
		registers[i] = dispatch.NewValue0(entry.Pos, OpPhi, uint64Type)
		registers[i].AddArg(zero)
	}

	for i, check := range checks {
		state := check.NewValue0I(program[i].pos, OpConst64, uint64Type, int64(states[i]))
		match := check.NewValue2(program[i].pos, OpEq64, f.Config.Types.Bool, pc, state)
		check.SetControl(match)
		check.Likely = BranchLikely
	}

	var vmResult *Value
	for i, instruction := range program {
		handler := handlers[i]
		if instruction.op == vmReturn {
			vmResult = registers[0]
			continue
		}

		outputs := append([]*Value(nil), registers...)
		switch instruction.op {
		case vmPushArg:
			outputs[instruction.depth] = instruction.arg
		case vmPushConst:
			outputs[instruction.depth] = vmConstant(handler, pc, instruction.pos, instruction.imm, rng.next(), encrypt)
		case vmNeg, vmCom:
			index := instruction.depth - 1
			op := OpNeg64
			if instruction.op == vmCom {
				op = OpCom64
			}
			outputs[index] = handler.NewValue1(instruction.pos, op, uint64Type, registers[index])
		default:
			left := instruction.depth - 2
			right := instruction.depth - 1
			op, ok := vmSSAOperation(instruction.op)
			if !ok {
				return fmt.Errorf("unsupported VM opcode %v", instruction.op)
			}
			outputs[left] = handler.NewValue2(instruction.pos, op, uint64Type, registers[left], registers[right])
		}

		nextPC := handler.NewValue0I(instruction.pos, OpConst64, uint64Type, int64(states[i+1]))
		pc.AddArg(nextPC)
		for j, output := range outputs {
			registers[j].AddArg(output)
		}
	}

	if vmResult == nil {
		return fmt.Errorf("VM program has no return value")
	}
	makeResult.SetArg(0, vmResult)
	ret.SetControl(makeResult)
	return nil
}

func vmSSAOperation(op vmOpcode) (Op, bool) {
	switch op {
	case vmAdd:
		return OpAdd64, true
	case vmSub:
		return OpSub64, true
	case vmMul:
		return OpMul64, true
	case vmAnd:
		return OpAnd64, true
	case vmOr:
		return OpOr64, true
	case vmXor:
		return OpXor64, true
	case vmLsh:
		return OpLsh64x64, true
	case vmRsh:
		return OpRsh64Ux64, true
	default:
		return OpInvalid, false
	}
}

func vmConstant(b *Block, pc *Value, pos src.XPos, value, mask uint64, encrypt bool) *Value {
	t := b.Func.Config.Types.UInt64
	if !encrypt {
		return b.NewValue0I(pos, OpConst64, t, int64(value))
	}
	if mask == 0 {
		mask = 0xa5a5a5a5a5a5a5a5
	}
	one := b.NewValue0I(pos, OpConst64, t, 1)
	pcNext := b.NewValue2(pos, OpAdd64, t, pc, one)
	even := b.NewValue2(pos, OpMul64, t, pc, pcNext)
	opaqueZero := b.NewValue2(pos, OpAnd64, t, even, one)
	encoded := b.NewValue0I(pos, OpConst64, t, int64(value^mask))
	key := b.NewValue0I(pos, OpConst64, t, int64(mask))
	dynamicKey := b.NewValue2(pos, OpXor64, t, key, opaqueZero)
	return b.NewValue2(pos, OpXor64, t, encoded, dynamicKey)
}

func findUint64Argument(f *Func) *Value {
	for _, v := range f.Entry.Values {
		if (v.Op == OpArg || v.Op == OpArgIntReg) && v.Type.Compare(f.Config.Types.UInt64) == types.CMPeq {
			return v
		}
	}
	return nil
}

func opaqueZero64(b *Block, source *Value) *Value {
	t := b.Func.Config.Types.UInt64
	one := b.NewValue0I(source.Pos, OpConst64, t, 1)
	next := b.NewValue2(source.Pos, OpAdd64, t, source, one)
	even := b.NewValue2(source.Pos, OpMul64, t, source, next)
	return b.NewValue2(source.Pos, OpAnd64, t, even, one)
}

func encodeUint64Constants(f *Func, rng *protectionRNG) (int, error) {
	_, _, _, err := pureUint64Return(f)
	if err != nil {
		return 0, err
	}
	source := findUint64Argument(f)
	if source == nil {
		return 0, fmt.Errorf("v1 requires at least one uint64 argument")
	}

	var constants []*Value
	for _, v := range f.Entry.Values {
		if v.Op == OpConst64 && v.Type.Compare(f.Config.Types.UInt64) == types.CMPeq && v.Uses != 0 {
			constants = append(constants, v)
		}
	}
	if len(constants) == 0 {
		return 0, fmt.Errorf("v1 found no uint64 constants to encode")
	}

	opaqueZero := opaqueZero64(f.Entry, source)
	for _, constant := range constants {
		mask := rng.next()
		if mask == 0 {
			mask = 0x3c6ef372fe94f82b
		}
		value := uint64(constant.AuxInt)
		encoded := f.Entry.NewValue0I(constant.Pos, OpConst64, constant.Type, int64(value^mask))
		key := f.Entry.NewValue0I(constant.Pos, OpConst64, constant.Type, int64(mask))
		dynamicKey := f.Entry.NewValue2(constant.Pos, OpXor64, constant.Type, key, opaqueZero)
		decoded := f.Entry.NewValue2(constant.Pos, OpXor64, constant.Type, encoded, dynamicKey)
		constant.copyOf(decoded)
	}
	return len(constants), nil
}

// encodeGeneralUint64Constants is the string-protection fallback for
// functions whose CFG or memory effects do not satisfy the pure v1 shape.
// The stack pointer is a dynamic, pointer-free value available at entry on
// 64-bit targets; its low bit is not assumed by the optimizer, so the same
// opaque-zero identity can decode constants in arbitrary control flow.
func encodeGeneralUint64Constants(f *Func, rng *protectionRNG) (int, error) {
	if f.Config.PtrSize != 8 {
		return 0, fmt.Errorf("general constant encoding requires a 64-bit target")
	}

	// Snapshot candidates before creating the decoder support values. In
	// particular, opaqueZero64 introduces its own Const64(1); collecting after
	// that point would make the decoder try to encode one of its inputs and
	// create a value cycle.
	type constantTarget struct {
		value *Value
		block *Block
	}
	var constants []constantTarget
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpConst64 && v.Type.Compare(f.Config.Types.UInt64) == types.CMPeq && v.Uses != 0 {
				constants = append(constants, constantTarget{value: v, block: b})
			}
		}
	}
	if len(constants) == 0 {
		return 0, fmt.Errorf("general encoding found no live uint64 constants")
	}

	var initMem *Value
	for _, v := range f.Entry.Values {
		if v.Op == OpInitMem {
			initMem = v
			break
		}
	}
	if initMem == nil {
		return 0, fmt.Errorf("general constant encoding found no entry memory")
	}
	sp := f.Entry.NewValue0(f.Entry.Pos, OpSP, f.Config.Types.Uintptr)
	source := f.Entry.NewValue2(f.Entry.Pos, OpConvert, f.Config.Types.UInt64, sp, initMem)
	opaqueZeroByBlock := make(map[*Block]*Value)
	for _, target := range constants {
		constant := target.value
		block := target.block
		opaqueZero := opaqueZeroByBlock[block]
		if opaqueZero == nil {
			opaqueZero = opaqueZero64(block, source)
			opaqueZeroByBlock[block] = opaqueZero
		}
		mask := rng.next()
		if mask == 0 {
			mask = 0x3c6ef372fe94f82b
		}
		value := uint64(constant.AuxInt)
		encoded := block.NewValue0I(constant.Pos, OpConst64, constant.Type, int64(value^mask))
		key := block.NewValue0I(constant.Pos, OpConst64, constant.Type, int64(mask))
		dynamicKey := block.NewValue2(constant.Pos, OpXor64, constant.Type, key, opaqueZero)
		decoded := block.NewValue2(constant.Pos, OpXor64, constant.Type, encoded, dynamicKey)
		constant.copyOf(decoded)
	}
	return len(constants), nil
}

func insertOpaqueDiamond(f *Func, rng *protectionRNG) error {
	entry, makeResult, root, err := pureUint64Return(f)
	if err != nil {
		return err
	}
	source := findUint64Argument(f)
	if source == nil {
		return fmt.Errorf("v1 requires at least one uint64 argument")
	}

	resultIndex := -1
	for i, v := range entry.Values {
		if v == makeResult {
			resultIndex = i
			break
		}
	}
	if resultIndex < 0 {
		return fmt.Errorf("return value is not owned by the entry block")
	}

	realPath := f.NewBlock(BlockPlain)
	fakePath := f.NewBlock(BlockPlain)
	merge := f.NewBlock(BlockPlain)
	ret := f.NewBlock(BlockRet)
	realPath.Pos = root.Pos
	fakePath.Pos = root.Pos
	merge.Pos = root.Pos
	ret.Pos = root.Pos

	conditionZero := opaqueZero64(entry, source)
	zero := entry.NewValue0I(root.Pos, OpConst64, f.Config.Types.UInt64, 0)
	condition := entry.NewValue2(root.Pos, OpEq64, f.Config.Types.Bool, conditionZero, zero)

	realZero := opaqueZero64(realPath, source)
	maskValue := rng.next()
	if maskValue == 0 {
		maskValue = 0xbb67ae8584caa73b
	}
	mask := realPath.NewValue0I(root.Pos, OpConst64, f.Config.Types.UInt64, int64(maskValue))
	mixed := fakePath.NewValue2(root.Pos, OpXor64, f.Config.Types.UInt64, source, mask)
	fakeZero := opaqueZero64(fakePath, mixed)
	noise := merge.NewValue0(root.Pos, OpPhi, f.Config.Types.UInt64)
	noise.AddArg(realZero)
	noise.AddArg(fakeZero)
	maskedResult := merge.NewValue2(root.Pos, OpXor64, f.Config.Types.UInt64, root, noise)

	makeResult.moveTo(ret, resultIndex)
	makeResult.SetArg(0, maskedResult)
	entry.Reset(BlockIf)
	entry.SetControl(condition)
	entry.Likely = BranchLikely
	entry.AddEdgeTo(realPath)
	entry.AddEdgeTo(fakePath)
	realPath.AddEdgeTo(merge)
	fakePath.AddEdgeTo(merge)
	merge.AddEdgeTo(ret)
	ret.SetControl(makeResult)
	return nil
}

// nativeOpaqueCoverage records the native control-flow work applied by
// //go:obf. Single-block arithmetic keeps the compact v1 diamond. Broader
// functions are protected by v2 edge dispatchers, so callers can distinguish
// complete CFG coverage from a budget-limited subset in OBFREPORT output.
type nativeOpaqueCoverage struct {
	legacy          bool
	wiredEdges      int
	candidateEdges  int
	wiredBlocks     int
	candidateBlocks int
	budget          int
}

func (c nativeOpaqueCoverage) report() string {
	if c.legacy {
		return "obf=bcf-v1"
	}
	scope := "full"
	if c.wiredEdges != c.candidateEdges {
		scope = "budgeted"
	}
	return fmt.Sprintf("obf=cfg-opaque-dispatch-v2 coverage=%s edges=%d/%d blocks=%d/%d budget=%d",
		scope, c.wiredEdges, c.candidateEdges, c.wiredBlocks, c.candidateBlocks, c.budget)
}

type nativeOpaqueEdge struct {
	source    *Block
	succIndex int
	target    *Block
}

// insertNativeOpaqueDispatch selects the compact v1 shape when possible and
// otherwise wraps normal CFG edges in seed-dependent opaque dispatch diamonds.
// The original target predecessor slot is retained and retargeted to the merge
// block, so existing Phi arguments and memory dependencies remain valid.
func insertNativeOpaqueDispatch(f *Func, rng *protectionRNG) (nativeOpaqueCoverage, error) {
	if _, _, _, err := pureUint64Return(f); err == nil {
		if err := insertOpaqueDiamond(f, rng); err != nil {
			return nativeOpaqueCoverage{}, err
		}
		return nativeOpaqueCoverage{legacy: true}, nil
	}

	if f.Config.PtrSize != 8 {
		return nativeOpaqueCoverage{}, fmt.Errorf("v2 requires a 64-bit target")
	}
	source, err := nativeOpaqueSource(f)
	if err != nil {
		return nativeOpaqueCoverage{}, err
	}

	reachable := ReachableBlocks(f)
	edges := make([]nativeOpaqueEdge, 0)
	blockSet := make(map[*Block]bool)
	for _, block := range f.Blocks {
		if !reachable[block.ID] || !nativeOpaqueSourceBlock(block) {
			continue
		}
		for succIndex, edge := range block.Succs {
			if edge.b == nil || edge.b == f.Entry {
				continue
			}
			edges = append(edges, nativeOpaqueEdge{source: block, succIndex: succIndex, target: edge.b})
			blockSet[block] = true
		}
	}
	if len(edges) == 0 {
		if err := insertNativeOpaqueReturnEnvelope(f, source, rng); err != nil {
			return nativeOpaqueCoverage{}, err
		}
		return nativeOpaqueCoverage{
			wiredEdges:      1,
			candidateEdges:  1,
			wiredBlocks:     1,
			candidateBlocks: 1,
			budget:          1,
		}, nil
	}

	// Fisher-Yates makes the bounded selection seed-dependent without adding a
	// sort or a function-size-dependent quadratic compile-time cost.
	for i := len(edges) - 1; i > 0; i-- {
		j := int(rng.next() % uint64(i+1))
		edges[i], edges[j] = edges[j], edges[i]
	}

	budget := base.Debug.ObfNativeBudget
	if budget <= 0 {
		budget = 48
	}
	limit := budget
	if limit > len(edges) {
		limit = len(edges)
	}
	covered := make(map[*Block]bool)
	for _, edge := range edges[:limit] {
		if err := wrapNativeOpaqueEdge(f, edge, source, rng); err != nil {
			return nativeOpaqueCoverage{}, err
		}
		covered[edge.source] = true
	}
	return nativeOpaqueCoverage{
		wiredEdges:      limit,
		candidateEdges:  len(edges),
		wiredBlocks:     len(covered),
		candidateBlocks: len(blockSet),
		budget:          budget,
	}, nil
}

// nativeOpaqueSourceBlock includes the ordinary conditional and plain CFG
// edges plus the post-defer continuation edges. The latter already carry their
// memory control in the source block, so edge wrapping leaves that ordering and
// both original successor indices intact.
func nativeOpaqueSourceBlock(block *Block) bool {
	switch block.Kind {
	case BlockPlain, BlockIf, BlockDefer:
		return true
	}
	return false
}

// nativeOpaqueSource provides a dynamic uint64 whose value is never used as a
// program result. It prefers an existing scalar parameter and otherwise uses
// the entry stack pointer, preserving support for call-heavy and cgo-adjacent
// native functions that have no suitable user arguments.
func nativeOpaqueSource(f *Func) (*Value, error) {
	if source := findUint64Argument(f); source != nil {
		return source, nil
	}
	var initMem *Value
	for _, value := range f.Entry.Values {
		if value.Op == OpInitMem {
			initMem = value
			break
		}
	}
	if initMem == nil {
		return nil, fmt.Errorf("v2 could not find entry memory for opaque dispatch")
	}
	sp := f.Entry.NewValue0(f.Entry.Pos, OpSP, f.Config.Types.Uintptr)
	return f.Entry.NewValue2(f.Entry.Pos, OpConvert, f.Config.Types.UInt64, sp, initMem), nil
}

// insertNativeOpaqueReturnEnvelope handles scalar-bool, void, and other
// single-return functions that have no normal edge to wrap. It moves the
// original return control behind an opaque entry diamond without altering the
// result tuple or its memory dependency.
func insertNativeOpaqueReturnEnvelope(f *Func, source *Value, rng *protectionRNG) error {
	entry := f.Entry
	if entry.Kind != BlockRet || len(entry.Succs) != 0 || entry.NumControls() != 1 {
		return fmt.Errorf("v2 found no normal CFG edges or compatible return envelope")
	}
	result := entry.Controls[0]
	resultIndex := -1
	for i, value := range entry.Values {
		if value == result {
			resultIndex = i
			break
		}
	}
	if resultIndex < 0 {
		return fmt.Errorf("v2 return control is not owned by the entry block")
	}

	left := f.NewBlock(BlockPlain)
	right := f.NewBlock(BlockPlain)
	merge := f.NewBlock(BlockPlain)
	ret := f.NewBlock(BlockRet)
	left.Pos = entry.Pos
	right.Pos = entry.Pos
	merge.Pos = entry.Pos
	ret.Pos = entry.Pos
	result.moveTo(ret, resultIndex)
	entry.Reset(BlockIf)
	entry.SetControl(nativeOpaqueCondition(entry, source, rng))
	entry.Likely = BranchUnknown
	entry.AddEdgeTo(left)
	entry.AddEdgeTo(right)
	left.AddEdgeTo(merge)
	right.AddEdgeTo(merge)
	merge.AddEdgeTo(ret)
	ret.SetControl(result)
	return nil
}

func nativeOpaqueCondition(block *Block, source *Value, rng *protectionRNG) *Value {
	maskValue := rng.next()
	if maskValue == 0 {
		maskValue = 0x3c6ef372fe94f82b
	}
	zero := opaqueZero64(block, source)
	mask := block.NewValue0I(block.Pos, OpConst64, block.Func.Config.Types.UInt64, int64(maskValue))
	mixed := block.NewValue2(block.Pos, OpXor64, block.Func.Config.Types.UInt64, zero, mask)
	return block.NewValue2(block.Pos, OpEq64, block.Func.Config.Types.Bool, mixed, mask)
}

// wrapNativeOpaqueEdge changes source -> target into source -> check ->
// (left|right) -> merge -> target. The old predecessor index in target is
// intentionally reused by merge, preserving every target Phi input verbatim.
func wrapNativeOpaqueEdge(f *Func, edge nativeOpaqueEdge, source *Value, rng *protectionRNG) error {
	if edge.source == nil || edge.target == nil || edge.succIndex < 0 || edge.succIndex >= len(edge.source.Succs) {
		return fmt.Errorf("v2 encountered a malformed CFG edge")
	}
	old := edge.source.Succs[edge.succIndex]
	if old.b != edge.target || old.i < 0 || old.i >= len(edge.target.Preds) {
		return fmt.Errorf("v2 edge changed before it could be wrapped")
	}
	if pred := edge.target.Preds[old.i]; pred.b != edge.source || pred.i != edge.succIndex {
		return fmt.Errorf("v2 encountered an inconsistent CFG edge")
	}

	check := f.NewBlock(BlockIf)
	left := f.NewBlock(BlockPlain)
	right := f.NewBlock(BlockPlain)
	merge := f.NewBlock(BlockPlain)
	check.Pos = edge.source.Pos
	left.Pos = edge.source.Pos
	right.Pos = edge.source.Pos
	merge.Pos = edge.target.Pos
	check.SetControl(nativeOpaqueCondition(check, source, rng))
	check.Likely = BranchUnknown

	// Keep the original target predecessor slot. A Phi input that was selected
	// on source -> target is still selected on merge -> target, while source
	// dominates both paths through check and merge.
	checkPredIndex := len(check.Preds)
	edge.source.Succs[edge.succIndex] = Edge{b: check, i: checkPredIndex}
	check.Preds = append(check.Preds, Edge{b: edge.source, i: edge.succIndex})
	mergeSuccIndex := len(merge.Succs)
	merge.Succs = append(merge.Succs, Edge{b: edge.target, i: old.i})
	edge.target.Preds[old.i] = Edge{b: merge, i: mergeSuccIndex}
	check.AddEdgeTo(left)
	check.AddEdgeTo(right)
	left.AddEdgeTo(merge)
	right.AddEdgeTo(merge)
	f.invalidateCFG()
	return nil
}

// vm2 is a register-based, control-flow preserving VM.  It deliberately
// accepts only pointer-free scalar SSA so that the dispatcher never creates
// hidden GC roots or memory ordering edges.  The source CFG is compiled into
// one state per value/terminator; Phi values are assigned on the outgoing edge
// that selects them.
type vm2InstructionKind uint8

const (
	vm2Exec vm2InstructionKind = iota
	vm2Jump
	vm2Branch
	vm2Return
)

type vm2Move struct {
	dst int
	src int
}

type vm2Edge struct {
	target int
	moves  []vm2Move
}

type vm2Instruction struct {
	kind  vm2InstructionKind
	value *Value
	op    Op
	dst   int
	args  []int
	imm   uint64
	pos   src.XPos

	next       int
	control    int
	edges      [2]vm2Edge
	returnReg  int
	resultType *types.Type
}

type vm2BlockPlan struct {
	block      *Block
	values     []*Value
	termKind   vm2InstructionKind
	control    *Value
	returnRoot *Value
	resultType *types.Type
	succs      [2]*Block
}

type vm2Program struct {
	instructions []vm2Instruction
	registers    []*Value
	reg          map[*Value]int
	blocks       []*Block
	blockFirst   map[*Block]int
	initMem      *Value
	sourceArg    *Value
	branches     int
}

const (
	vm2MaxBlocks       = 128
	vm2MaxInstructions = 512
	vm2MaxRegisters    = 256
)

func vm2ScalarType(f *Func, t *types.Type) bool {
	return t != nil && t.Compare(f.Config.Types.UInt64) == types.CMPeq
}

func vm2BoolType(f *Func, t *types.Type) bool {
	return t != nil && t.Compare(f.Config.Types.Bool) == types.CMPeq
}

func vm2ValueType(f *Func, t *types.Type) bool {
	return vm2ScalarType(f, t) || vm2BoolType(f, t)
}

func vm2ArgReg(reg map[*Value]int, v *Value) (int, bool) {
	i, ok := reg[v]
	return i, ok
}

func vm2ValueUsesRegister(v *Value) bool {
	return v.Uses != 0
}

func vm2SupportedOp(f *Func, v *Value, reg map[*Value]int) error {
	if !vm2ValueType(f, v.Type) {
		return fmt.Errorf("unsupported result type %v at %v", v.Type, v)
	}
	need := func(n int) error {
		if len(v.Args) != n {
			return fmt.Errorf("malformed %v at %v", v.Op, v)
		}
		for _, a := range v.Args {
			if _, ok := reg[a]; !ok {
				return fmt.Errorf("operand %v of %v is not a VM scalar", a, v)
			}
		}
		return nil
	}
	scalarArgs := func() error {
		if err := need(2); err != nil {
			return err
		}
		for _, a := range v.Args {
			if !vm2ScalarType(f, a.Type) {
				return fmt.Errorf("%v requires uint64 operands at %v", v.Op, v)
			}
		}
		if !vm2ScalarType(f, v.Type) {
			return fmt.Errorf("%v requires a uint64 result at %v", v.Op, v)
		}
		return nil
	}
	boolArgs := func() error {
		if err := need(2); err != nil {
			return err
		}
		for _, a := range v.Args {
			if !vm2BoolType(f, a.Type) {
				return fmt.Errorf("%v requires bool operands at %v", v.Op, v)
			}
		}
		if !vm2BoolType(f, v.Type) {
			return fmt.Errorf("%v requires a bool result at %v", v.Op, v)
		}
		return nil
	}

	switch v.Op {
	case OpArg, OpArgIntReg:
		if len(v.Args) != 0 {
			return fmt.Errorf("malformed argument %v", v)
		}
	case OpConst64:
		if !vm2ScalarType(f, v.Type) {
			return fmt.Errorf("Const64 has non-uint64 type %v at %v", v.Type, v)
		}
	case OpConstBool:
		if !vm2BoolType(f, v.Type) || v.AuxInt < 0 || v.AuxInt > 1 {
			return fmt.Errorf("malformed ConstBool at %v", v)
		}
	case OpPhi:
		if !vm2ValueType(f, v.Type) {
			return fmt.Errorf("unsupported Phi type %v at %v", v.Type, v)
		}
		for _, a := range v.Args {
			if _, ok := reg[a]; !ok || a.Type.Compare(v.Type) != types.CMPeq {
				return fmt.Errorf("Phi at %v has an unsupported operand", v)
			}
		}
	case OpCopy:
		if err := need(1); err != nil {
			return err
		}
		if v.Args[0].Type.Compare(v.Type) != types.CMPeq {
			return fmt.Errorf("Copy changes type at %v", v)
		}
	case OpNeg64, OpCom64:
		if len(v.Args) != 1 || !vm2ScalarType(f, v.Type) || !vm2ScalarType(f, v.Args[0].Type) {
			return fmt.Errorf("%v requires one uint64 operand at %v", v.Op, v)
		}
	case OpAdd64, OpSub64, OpMul64, OpAnd64, OpOr64, OpXor64,
		OpLsh64x64, OpRsh64Ux64:
		if err := scalarArgs(); err != nil {
			return err
		}
	case OpEq64, OpNeq64, OpLess64U, OpLeq64U:
		if err := need(2); err != nil {
			return err
		}
		for _, a := range v.Args {
			if !vm2ScalarType(f, a.Type) {
				return fmt.Errorf("%v requires uint64 operands at %v", v.Op, v)
			}
		}
		if !vm2BoolType(f, v.Type) {
			return fmt.Errorf("%v must produce bool at %v", v.Op, v)
		}
	case OpAndB, OpOrB, OpEqB, OpNeqB:
		return boolArgs()
	case OpNot:
		if len(v.Args) != 1 || !vm2BoolType(f, v.Type) || !vm2BoolType(f, v.Args[0].Type) {
			return fmt.Errorf("Not requires one bool operand at %v", v)
		}
	case OpCondSelect:
		if len(v.Args) != 3 || !vm2BoolType(f, v.Args[0].Type) || !vm2ValueType(f, v.Type) ||
			v.Args[1].Type.Compare(v.Type) != types.CMPeq || v.Args[2].Type.Compare(v.Type) != types.CMPeq {
			return fmt.Errorf("malformed CondSelect at %v", v)
		}
		if _, ok := reg[v.Args[0]]; !ok {
			return fmt.Errorf("CondSelect condition is not a VM value at %v", v)
		}
	default:
		return fmt.Errorf("unsupported SSA operation %v at %v", v.Op, v)
	}
	return nil
}

func vm2OrderBlockValues(b *Block, reg map[*Value]int) ([]*Value, error) {
	state := make(map[*Value]uint8)
	ordered := make([]*Value, 0, len(b.Values))
	var visit func(*Value) error
	visit = func(v *Value) error {
		if _, ok := reg[v]; !ok || v.Block != b {
			return nil
		}
		if v.Op == OpArg || v.Op == OpArgIntReg || v.Op == OpPhi {
			return nil
		}
		switch state[v] {
		case 1:
			return fmt.Errorf("cyclic intra-block value graph at %v", v)
		case 2:
			return nil
		}
		state[v] = 1
		for _, a := range v.Args {
			if a.Block == b {
				if err := visit(a); err != nil {
					return err
				}
			}
		}
		state[v] = 2
		ordered = append(ordered, v)
		return nil
	}
	for _, v := range b.Values {
		if _, ok := reg[v]; !ok {
			continue
		}
		if err := visit(v); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func vm2PhiMoves(target *Block, predIndex int, reg map[*Value]int) ([]vm2Move, error) {
	moves := make([]vm2Move, 0)
	for _, v := range target.Values {
		if v.Op != OpPhi {
			continue
		}
		dst, ok := reg[v]
		if !ok {
			continue
		}
		if predIndex < 0 || predIndex >= len(v.Args) {
			return nil, fmt.Errorf("Phi %v has no argument for predecessor %d", v, predIndex)
		}
		srcReg, ok := reg[v.Args[predIndex]]
		if !ok {
			return nil, fmt.Errorf("Phi %v selects unsupported value %v", v, v.Args[predIndex])
		}
		moves = append(moves, vm2Move{dst: dst, src: srcReg})
	}
	return moves, nil
}

func buildVM2Program(f *Func) (*vm2Program, error) {
	reachable := ReachableBlocks(f)
	blocks := make([]*Block, 0, len(f.Blocks))
	blocks = append(blocks, f.Entry)
	for _, b := range f.Blocks {
		if b != f.Entry && reachable[b.ID] {
			blocks = append(blocks, b)
		}
	}
	if len(blocks) > vm2MaxBlocks {
		return nil, fmt.Errorf("v2 block limit exceeded (%d > %d)", len(blocks), vm2MaxBlocks)
	}

	p := &vm2Program{reg: make(map[*Value]int), blocks: blocks, blockFirst: make(map[*Block]int)}
	for _, b := range blocks {
		for _, v := range b.Values {
			if v.Op == OpInitMem {
				if p.initMem != nil && p.initMem != v {
					return nil, fmt.Errorf("multiple InitMem values are not supported")
				}
				p.initMem = v
				continue
			}
			if !vm2ValueUsesRegister(v) || v.Op == OpMakeResult {
				continue
			}
			if !vm2ValueType(f, v.Type) {
				return nil, fmt.Errorf("unsupported live value type %v at %v", v.Type, v)
			}
			if _, ok := p.reg[v]; !ok {
				p.reg[v] = len(p.registers)
				p.registers = append(p.registers, v)
			}
		}
	}
	if p.initMem == nil {
		return nil, fmt.Errorf("v2 requires an InitMem return chain")
	}
	p.sourceArg = findUint64Argument(f)
	if p.sourceArg == nil {
		return nil, fmt.Errorf("v2 requires at least one uint64 argument")
	}
	if len(p.registers) > vm2MaxRegisters {
		return nil, fmt.Errorf("v2 register limit exceeded (%d > %d)", len(p.registers), vm2MaxRegisters)
	}

	plans := make([]vm2BlockPlan, 0, len(blocks))
	for _, b := range blocks {
		switch b.Kind {
		case BlockPlain:
			if len(b.Succs) != 1 {
				return nil, fmt.Errorf("plain block %v has %d successors", b, len(b.Succs))
			}
		case BlockIf:
			if len(b.Succs) != 2 || b.Controls[0] == nil || !vm2BoolType(f, b.Controls[0].Type) {
				return nil, fmt.Errorf("conditional block %v is not a scalar boolean branch", b)
			}
			if _, ok := p.reg[b.Controls[0]]; !ok {
				return nil, fmt.Errorf("branch condition %v is not a VM value", b.Controls[0])
			}
			p.branches++
		case BlockRet:
			if len(b.Succs) != 0 || b.Controls[0] == nil || b.Controls[0].Op != OpMakeResult {
				return nil, fmt.Errorf("return block %v has an unsupported result", b)
			}
		default:
			return nil, fmt.Errorf("block kind %s in %v is not supported by v2", b.Kind, b)
		}
		values, err := vm2OrderBlockValues(b, p.reg)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			if err := vm2SupportedOp(f, v, p.reg); err != nil {
				return nil, err
			}
		}
		plan := vm2BlockPlan{block: b, values: values}
		switch b.Kind {
		case BlockPlain:
			plan.termKind = vm2Jump
			plan.succs[0] = b.Succs[0].b
		case BlockIf:
			plan.termKind = vm2Branch
			plan.control = b.Controls[0]
			plan.succs[0] = b.Succs[0].b
			plan.succs[1] = b.Succs[1].b
		case BlockRet:
			plan.termKind = vm2Return
			result := b.Controls[0]
			if len(result.Args) != 2 || result.Args[1] != p.initMem || !vm2ValueType(f, result.Args[0].Type) {
				return nil, fmt.Errorf("v2 requires exactly one scalar result and InitMem in %v", b)
			}
			if _, ok := p.reg[result.Args[0]]; !ok {
				return nil, fmt.Errorf("return value %v is not a VM value", result.Args[0])
			}
			plan.returnRoot = result.Args[0]
			plan.resultType = result.Type
		}
		plans = append(plans, plan)
	}

	for _, plan := range plans {
		p.blockFirst[plan.block] = len(p.instructions)
		for _, v := range plan.values {
			args := make([]int, len(v.Args))
			for i, a := range v.Args {
				if r, ok := p.reg[a]; ok {
					args[i] = r
				} else {
					return nil, fmt.Errorf("value %v has unsupported operand %v", v, a)
				}
			}
			inst := vm2Instruction{kind: vm2Exec, value: v, op: v.Op, dst: p.reg[v], args: args, pos: v.Pos}
			if v.Op == OpConst64 {
				inst.imm = v.AuxUnsigned()
			}
			p.instructions = append(p.instructions, inst)
		}
		term := vm2Instruction{kind: plan.termKind, pos: plan.block.Pos}
		switch plan.termKind {
		case vm2Jump:
			term.edges[0] = vm2Edge{moves: nil}
		case vm2Branch:
			term.control = p.reg[plan.control]
		case vm2Return:
			term.returnReg = p.reg[plan.returnRoot]
			term.resultType = plan.resultType
		}
		p.instructions = append(p.instructions, term)
	}
	if len(p.instructions) == 0 || len(p.instructions) > vm2MaxInstructions {
		return nil, fmt.Errorf("v2 instruction limit exceeded (%d > %d)", len(p.instructions), vm2MaxInstructions)
	}

	for i := range p.instructions {
		if p.instructions[i].kind == vm2Exec {
			p.instructions[i].next = i + 1
		}
	}
	for _, plan := range plans {
		termIndex := p.blockFirst[plan.block] + len(plan.values)
		term := &p.instructions[termIndex]
		for edgeIndex, target := range plan.succs {
			if target == nil {
				continue
			}
			targetFirst, ok := p.blockFirst[target]
			if !ok {
				return nil, fmt.Errorf("edge from %v reaches unreachable block %v", plan.block, target)
			}
			moves, err := vm2PhiMoves(target, plan.block.Succs[edgeIndex].i, p.reg)
			if err != nil {
				return nil, err
			}
			term.edges[edgeIndex] = vm2Edge{target: targetFirst, moves: moves}
		}
	}
	return p, nil
}

// vm3 groups consecutive VM execution instructions into super-instructions.
// A block terminator may share the same handler as the final execution unit;
// this removes a dispatcher round trip without changing edge semantics.
type vm3Unit struct {
	kind  vm2InstructionKind
	first int
	count int
	term  int
	pos   src.XPos

	next       int
	control    int
	edges      [2]vm2Edge
	returnReg  int
	resultType *types.Type
}

type vm3Program struct {
	source        *vm2Program
	units         []vm3Unit
	sourceToUnit  []int
	buckets       int
	checks        int
	decoys        int
	aliases       int
	fused         int
	terminalFused int
}

const vm3MaxBundleOps = 8

func vm3BucketCount(states int) int {
	switch {
	case states >= 64:
		return 8
	case states >= 24:
		return 4
	case states >= 8:
		return 2
	default:
		return 1
	}
}

func vm2TerminatorIndices(source *vm2Program) map[int]bool {
	terms := make(map[int]bool, len(source.blocks))
	if len(source.blocks) == 0 {
		for i, inst := range source.instructions {
			if inst.kind != vm2Exec {
				terms[i] = true
			}
		}
		return terms
	}
	for i, block := range source.blocks {
		first := source.blockFirst[block]
		end := len(source.instructions)
		if i+1 < len(source.blocks) {
			end = source.blockFirst[source.blocks[i+1]]
		}
		if end > first {
			terms[end-1] = true
		}
	}
	return terms
}

func buildVM3Program(source *vm2Program, rng *protectionRNG) (*vm3Program, error) {
	if source == nil || len(source.instructions) == 0 || rng == nil {
		return nil, fmt.Errorf("invalid v3 source program")
	}
	p := &vm3Program{
		source:       source,
		sourceToUnit: make([]int, len(source.instructions)),
	}
	termIndices := vm2TerminatorIndices(source)
	for i := 0; i < len(source.instructions); {
		inst := &source.instructions[i]
		unit := vm3Unit{kind: inst.kind, first: i, term: i, pos: inst.pos}
		if inst.kind == vm2Exec {
			unit.term = -1
			run := 0
			for i+run < len(source.instructions) && source.instructions[i+run].kind == vm2Exec && run < vm3MaxBundleOps {
				run++
			}
			width := 2 + int(rng.next()%uint64(vm3MaxBundleOps-1))
			if width > run {
				width = run
			}
			unit.count = width
			for j := 0; j < width; j++ {
				p.sourceToUnit[i+j] = len(p.units)
			}
			i += width
			if i < len(source.instructions) && termIndices[i] && source.instructions[i].kind != vm2Branch {
				unit.kind = source.instructions[i].kind
				unit.term = i
				unit.pos = source.instructions[i].pos
				p.sourceToUnit[i] = len(p.units)
				p.terminalFused++
				i++
			}
		} else {
			p.sourceToUnit[i] = len(p.units)
			i++
		}
		p.units = append(p.units, unit)
	}

	for i := range p.units {
		unit := &p.units[i]
		switch unit.kind {
		case vm2Exec:
			last := &source.instructions[unit.first+unit.count-1]
			if last.next < 0 || last.next >= len(p.sourceToUnit) {
				return nil, fmt.Errorf("v3 execution unit has invalid target %d", last.next)
			}
			unit.next = p.sourceToUnit[last.next]
		case vm2Jump, vm2Branch:
			term := &source.instructions[unit.term]
			unit.control = term.control
			for edgeIndex, edge := range term.edges {
				if edge.target < 0 || edge.target >= len(p.sourceToUnit) {
					return nil, fmt.Errorf("v3 edge has invalid target %d", edge.target)
				}
				unit.edges[edgeIndex] = vm2Edge{target: p.sourceToUnit[edge.target], moves: edge.moves}
				if unit.kind == vm2Jump {
					break
				}
			}
		case vm2Return:
			term := &source.instructions[unit.term]
			unit.returnReg = term.returnReg
			unit.resultType = term.resultType
		default:
			return nil, fmt.Errorf("invalid v3 unit kind %d", unit.kind)
		}
	}
	p.buckets = vm3BucketCount(len(p.units))
	p.fused = len(source.instructions) - len(p.units)
	return p, nil
}

type vm3DispatchKind uint8

const (
	vm3InitialEdge vm3DispatchKind = iota
	vm3ExecEdge
	vm3MoveEdge
	vm3InvalidEdge
)

type vm3DispatchInfo struct {
	kind         vm3DispatchKind
	unit         *vm3Unit
	computeBlock *Block
	moves        []vm2Move
	next         int
}

func vm3EncodedConstant(b *Block, pos src.XPos, value uint64, rng *protectionRNG, encrypt bool, zero *Value) *Value {
	if !encrypt {
		return b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(value))
	}
	mask := rng.next()
	if mask == 0 {
		mask = 0x9e3779b97f4a7c15
	}
	encoded := b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(value^mask))
	key := b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(mask))
	if zero == nil {
		return b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, encoded, key)
	}
	dynamicKey := b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, key, zero)
	return b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, encoded, dynamicKey)
}

func vm3MaskedState(b *Block, pos src.XPos, state, mask uint64, dynamicMask *Value) *Value {
	if dynamicMask == nil {
		return b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(state))
	}
	encoded := b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(state^mask))
	return b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, encoded, dynamicMask)
}

func vm2EmitValue(b *Block, inst *vm2Instruction, regs []*Value, pc, zero *Value, rng *protectionRNG, encrypt bool) (*Value, error) {
	v := inst.value
	t := v.Type
	arg := func(i int) (*Value, error) {
		if i < 0 || i >= len(inst.args) || inst.args[i] < 0 || inst.args[i] >= len(regs) {
			return nil, fmt.Errorf("bad VM operand index for %v", v)
		}
		return regs[inst.args[i]], nil
	}
	switch v.Op {
	case OpConst64:
		return vm3EncodedConstant(b, v.Pos, inst.imm, rng, encrypt, zero), nil
	case OpConstBool:
		return b.NewValue0I(v.Pos, OpConstBool, t, v.AuxInt), nil
	case OpCopy:
		a, err := arg(0)
		if err != nil {
			return nil, err
		}
		return b.NewValue1(v.Pos, OpCopy, t, a), nil
	case OpNeg64, OpCom64, OpNot:
		a, err := arg(0)
		if err != nil {
			return nil, err
		}
		return b.NewValue1(v.Pos, v.Op, t, a), nil
	case OpCondSelect:
		c, err := arg(0)
		if err != nil {
			return nil, err
		}
		x, err := arg(1)
		if err != nil {
			return nil, err
		}
		y, err := arg(2)
		if err != nil {
			return nil, err
		}
		return b.NewValue3(v.Pos, OpCondSelect, t, c, x, y), nil
	default:
		if len(inst.args) != 2 {
			return nil, fmt.Errorf("unsupported VM arity for %v", v)
		}
		x, err := arg(0)
		if err != nil {
			return nil, err
		}
		y, err := arg(1)
		if err != nil {
			return nil, err
		}
		switch v.Op {
		case OpAdd64, OpSub64, OpMul64, OpAnd64, OpOr64, OpXor64,
			OpLsh64x64, OpRsh64Ux64, OpEq64, OpNeq64, OpLess64U, OpLeq64U,
			OpAndB, OpOrB, OpEqB, OpNeqB:
			return b.NewValue2(v.Pos, v.Op, t, x, y), nil
		default:
			return nil, fmt.Errorf("unsupported VM operation %v", v.Op)
		}
	}
}

func vm2InitialRegisterValue(entry *Block, v *Value, zero64, zeroBool *Value) *Value {
	switch v.Op {
	case OpArg, OpArgIntReg:
		return v
	case OpPhi:
		if vm2BoolType(entry.Func, v.Type) {
			return zeroBool
		}
		return zero64
	default:
		if vm2BoolType(entry.Func, v.Type) {
			return zeroBool
		}
		return zero64
	}
}

func vm2CheckPermutation(n int, rng *protectionRNG) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	for i := len(order) - 1; i > 0; i-- {
		j := int(rng.next() % uint64(i+1))
		order[i], order[j] = order[j], order[i]
	}
	return order
}

type vm3CheckSpec struct {
	state uint64
	unit  int
	decoy bool
	alias bool
}

type vm3CheckNode struct {
	block *Block
	spec  vm3CheckSpec
}

func vm3StateForBucket(rng *protectionRNG, seen map[uint64]bool, bucketKey, bucketMask uint64, bucket int) uint64 {
	low := (uint64(bucket) ^ bucketKey) & bucketMask
	for {
		state := (rng.next() &^ bucketMask) | low
		if state != 0 && !seen[state] {
			seen[state] = true
			return state
		}
	}
}

func vm3ShuffleChecks(checks []vm3CheckSpec, rng *protectionRNG) {
	for i := len(checks) - 1; i > 0; i-- {
		j := int(rng.next() % uint64(i+1))
		checks[i], checks[j] = checks[j], checks[i]
	}
}

func vm3EmitUnit(b *Block, p *vm3Program, unit *vm3Unit, regs []*Value, pc, zero *Value, rng *protectionRNG, encrypt bool) ([]*Value, error) {
	if unit.count <= 0 {
		return nil, fmt.Errorf("invalid v3 execution unit")
	}
	local := append([]*Value(nil), regs...)
	changed := make([]*Value, len(regs))
	for i := 0; i < unit.count; i++ {
		inst := &p.source.instructions[unit.first+i]
		if inst.kind != vm2Exec {
			return nil, fmt.Errorf("v3 execution unit crosses a terminator")
		}
		value, err := vm2EmitValue(b, inst, local, pc, zero, rng, encrypt)
		if err != nil {
			return nil, err
		}
		local[inst.dst] = value
		changed[inst.dst] = value
	}
	return changed, nil
}

func installVM4Program(f *Func, p *vm3Program, encrypt bool, aliasCount, budget int) error {
	if p == nil || p.source == nil || len(p.units) == 0 || p.source.initMem == nil || p.source.sourceArg == nil || p.buckets <= 0 {
		return fmt.Errorf("invalid v3 VM program")
	}
	source := p.source
	entry := f.Entry
	for len(entry.Succs) != 0 {
		entry.removeEdge(0)
	}
	entry.Reset(BlockPlain)
	entry.Likely = BranchUnknown

	rng := newProtectionRNGDomain(f, "vm3-state")
	bucketMask := uint64(p.buckets - 1)
	bucketKey := rng.next()
	stateMasks := make([]uint64, p.buckets)
	for bucket := range stateMasks {
		stateMasks[bucket] = rng.next()
		if stateMasks[bucket] == 0 {
			stateMasks[bucket] = 0x9e3779b97f4a7c15 ^ uint64(bucket)
		}
	}
	seen := make(map[uint64]bool, len(p.units)*2+1)
	states := make([]uint64, len(p.units))
	unitBuckets := make([]int, len(p.units))
	checksByBucket := make([][]vm3CheckSpec, p.buckets)
	stateOrder := vm2CheckPermutation(len(p.units), rng)
	for rank, unitIndex := range stateOrder {
		bucket := rank % p.buckets
		state := vm3StateForBucket(rng, seen, bucketKey, bucketMask, bucket)
		states[unitIndex] = state
		unitBuckets[unitIndex] = bucket
		checksByBucket[bucket] = append(checksByBucket[bucket], vm3CheckSpec{state: state, unit: unitIndex})
	}

	decoyCount := (len(p.units) + 2) / 3
	if len(p.units) >= 4 && decoyCount < p.buckets {
		decoyCount = p.buckets
	}
	if decoyCount > 96 {
		decoyCount = 96
	}
	decoyOffset := int(rng.next() % uint64(p.buckets))
	for i := 0; i < decoyCount; i++ {
		bucket := (i + decoyOffset) % p.buckets
		state := vm3StateForBucket(rng, seen, bucketKey, bucketMask, bucket)
		checksByBucket[bucket] = append(checksByBucket[bucket], vm3CheckSpec{state: state, unit: -1, decoy: true})
	}
	if aliasCount > 0 {
		if aliasCount > budget/32 {
			aliasCount = budget / 32
		}
		if aliasCount < 0 {
			aliasCount = 0
		}
		for i := 0; i < aliasCount; i++ {
			unitIndex := stateOrder[(i*7)%len(stateOrder)]
			bucket := unitBuckets[unitIndex]
			state := vm3StateForBucket(rng, seen, bucketKey, bucketMask, bucket)
			checksByBucket[bucket] = append(checksByBucket[bucket], vm3CheckSpec{state: state, unit: unitIndex, alias: true})
		}
	}
	invalidState := vm3StateForBucket(rng, seen, bucketKey, bucketMask, 0)
	for bucket := range checksByBucket {
		vm3ShuffleChecks(checksByBucket[bucket], rng)
		if len(checksByBucket[bucket]) == 0 {
			return fmt.Errorf("v3 bucket %d has no checks", bucket)
		}
	}
	p.aliases = aliasCount
	p.checks = len(p.units) + decoyCount + aliasCount
	p.decoys = decoyCount

	dispatch := f.NewBlock(BlockPlain)
	dispatch.Pos = entry.Pos
	handlers := make([]*Block, len(p.units))
	for i, unit := range p.units {
		handlers[i] = f.NewBlock(BlockPlain)
		handlers[i].Pos = unit.pos
	}
	invalid := f.NewBlock(BlockPlain)
	invalid.Pos = entry.Pos
	selectors := make([]*Block, p.buckets-1)
	for i := range selectors {
		selectors[i] = f.NewBlock(BlockIf)
		selectors[i].Pos = entry.Pos
	}

	checkNodes := make([][]vm3CheckNode, p.buckets)
	bucketHeads := make([]*Block, p.buckets)
	for bucket, specs := range checksByBucket {
		checkNodes[bucket] = make([]vm3CheckNode, len(specs))
		for i, spec := range specs {
			block := f.NewBlock(BlockIf)
			block.Pos = entry.Pos
			if !spec.decoy {
				block.Pos = p.units[spec.unit].pos
			}
			checkNodes[bucket][i] = vm3CheckNode{block: block, spec: spec}
		}
		bucketHeads[bucket] = checkNodes[bucket][0].block
	}

	entry.AddEdgeTo(dispatch)
	bucketOrder := vm2CheckPermutation(p.buckets, rng)
	if len(selectors) == 0 {
		dispatch.AddEdgeTo(bucketHeads[0])
	} else {
		dispatch.AddEdgeTo(selectors[0])
		for i, selector := range selectors {
			selector.AddEdgeTo(bucketHeads[bucketOrder[i]])
			if i+1 < len(selectors) {
				selector.AddEdgeTo(selectors[i+1])
			} else {
				selector.AddEdgeTo(bucketHeads[bucketOrder[len(bucketOrder)-1]])
			}
		}
	}

	infos := make(map[*Block]vm3DispatchInfo, len(p.units)*2+2)
	infos[entry] = vm3DispatchInfo{kind: vm3InitialEdge, next: 0}
	for i := range p.units {
		unit := &p.units[i]
		switch unit.kind {
		case vm2Exec:
			handlers[i].AddEdgeTo(dispatch)
			infos[handlers[i]] = vm3DispatchInfo{kind: vm3ExecEdge, unit: unit, computeBlock: handlers[i], next: unit.next}
		case vm2Jump:
			handlers[i].AddEdgeTo(dispatch)
			infos[handlers[i]] = vm3DispatchInfo{kind: vm3MoveEdge, unit: unit, computeBlock: handlers[i], moves: unit.edges[0].moves, next: unit.edges[0].target}
		case vm2Branch:
			thenBlock := f.NewBlock(BlockPlain)
			elseBlock := f.NewBlock(BlockPlain)
			thenBlock.Pos = unit.pos
			elseBlock.Pos = unit.pos
			handlers[i].AddEdgeTo(thenBlock)
			handlers[i].AddEdgeTo(elseBlock)
			thenBlock.AddEdgeTo(dispatch)
			elseBlock.AddEdgeTo(dispatch)
			infos[thenBlock] = vm3DispatchInfo{kind: vm3MoveEdge, unit: unit, computeBlock: handlers[i], moves: unit.edges[0].moves, next: unit.edges[0].target}
			infos[elseBlock] = vm3DispatchInfo{kind: vm3MoveEdge, unit: unit, computeBlock: handlers[i], moves: unit.edges[1].moves, next: unit.edges[1].target}
		case vm2Return:
			// The handler becomes BlockRet after dispatcher Phis are complete.
		default:
			return fmt.Errorf("invalid v3 unit kind %d", unit.kind)
		}
	}
	for bucket := range checkNodes {
		for i := range checkNodes[bucket] {
			node := &checkNodes[bucket][i]
			if node.spec.decoy {
				node.block.AddEdgeTo(invalid)
			} else {
				node.block.AddEdgeTo(handlers[node.spec.unit])
			}
			if i+1 < len(checkNodes[bucket]) {
				node.block.AddEdgeTo(checkNodes[bucket][i+1].block)
			} else {
				node.block.AddEdgeTo(invalid)
			}
		}
	}
	invalid.AddEdgeTo(dispatch)
	infos[invalid] = vm3DispatchInfo{kind: vm3InvalidEdge, next: -1}

	uint64Type := f.Config.Types.UInt64
	pc := dispatch.NewValue0(entry.Pos, OpPhi, uint64Type)
	registers := make([]*Value, len(source.registers))
	for i, v := range source.registers {
		registers[i] = dispatch.NewValue0(v.Pos, OpPhi, v.Type)
	}
	zero64 := entry.NewValue0I(entry.Pos, OpConst64, uint64Type, 0)
	zeroBool := entry.NewValue0I(entry.Pos, OpConstBool, f.Config.Types.Bool, 0)
	var entryOpaqueZero, dispatchOpaqueZero *Value
	var entryDynamicMask *Value
	dispatchDynamicMasks := make([]*Value, p.buckets)
	if encrypt {
		entryOpaqueZero = opaqueZero64(entry, source.sourceArg)
		dispatchOpaqueZero = opaqueZero64(dispatch, pc)
		entryMask := entry.NewValue0I(entry.Pos, OpConst64, uint64Type, int64(stateMasks[unitBuckets[0]]))
		entryDynamicMask = entry.NewValue2(entry.Pos, OpXor64, uint64Type, entryMask, entryOpaqueZero)
		for bucket := range dispatchDynamicMasks {
			mask := dispatch.NewValue0I(entry.Pos, OpConst64, uint64Type, int64(stateMasks[bucket]))
			dispatchDynamicMasks[bucket] = dispatch.NewValue2(entry.Pos, OpXor64, uint64Type, mask, dispatchOpaqueZero)
		}
	}

	// Every edge into dispatch contributes one state and a complete register
	// snapshot. A fused execution unit computes against a local register view,
	// then publishes all changed registers through the dispatcher Phis once.
	computedByBlock := make(map[*Block][]*Value)
	for _, edge := range dispatch.Preds {
		info, ok := infos[edge.b]
		if !ok {
			return fmt.Errorf("missing v3 dispatcher metadata for %v", edge.b)
		}
		var state *Value
		switch info.kind {
		case vm3InitialEdge:
			state = vm3MaskedState(entry, entry.Pos, states[0], stateMasks[unitBuckets[0]], entryDynamicMask)
		case vm3InvalidEdge:
			state = vm3MaskedState(edge.b, edge.b.Pos, invalidState, stateMasks[0], dispatchDynamicMasks[0])
		default:
			if info.next < 0 || info.next >= len(states) {
				return fmt.Errorf("invalid v3 dispatcher target %d", info.next)
			}
			state = vm3MaskedState(edge.b, edge.b.Pos, states[info.next], stateMasks[unitBuckets[info.next]], dispatchDynamicMasks[unitBuckets[info.next]])
		}
		pc.AddArg(state)

		var computed []*Value
		if info.unit != nil && info.unit.count > 0 {
			computed = computedByBlock[info.computeBlock]
			if computed != nil {
				// The same handler can feed both branch edges. Reuse the values
				// emitted in that handler instead of duplicating the computation.
			} else {
				var err error
				computed, err = vm3EmitUnit(info.computeBlock, p, info.unit, registers, pc, dispatchOpaqueZero, rng, encrypt)
				if err != nil {
					return err
				}
				computedByBlock[info.computeBlock] = computed
			}
		}
		moveByDst := make(map[int]int, len(info.moves))
		for _, move := range info.moves {
			moveByDst[move.dst] = move.src
		}
		for i, phi := range registers {
			var value *Value
			if info.kind == vm3InitialEdge {
				value = vm2InitialRegisterValue(entry, source.registers[i], zero64, zeroBool)
			} else if srcReg, ok := moveByDst[i]; ok {
				value = registers[srcReg]
			} else if computed != nil && computed[i] != nil {
				value = computed[i]
			} else {
				value = phi
			}
			phi.AddArg(value)
		}
	}

	if len(selectors) != 0 {
		key := vm3EncodedConstant(dispatch, entry.Pos, bucketKey, rng, encrypt, dispatchOpaqueZero)
		mixed := dispatch.NewValue2(entry.Pos, OpXor64, uint64Type, pc, key)
		mask := vm3EncodedConstant(dispatch, entry.Pos, bucketMask, rng, encrypt, dispatchOpaqueZero)
		bucketValue := dispatch.NewValue2(entry.Pos, OpAnd64, uint64Type, mixed, mask)
		for i, selector := range selectors {
			bucket := bucketOrder[i]
			expected := vm3EncodedConstant(selector, selector.Pos, uint64(bucket), rng, encrypt, dispatchOpaqueZero)
			match := selector.NewValue2(selector.Pos, OpEq64, f.Config.Types.Bool, bucketValue, expected)
			selector.SetControl(match)
			selector.Likely = BranchUnknown
		}
	}
	for bucket := range checkNodes {
		for i := range checkNodes[bucket] {
			node := &checkNodes[bucket][i]
			state := vm3MaskedState(node.block, node.block.Pos, node.spec.state, stateMasks[bucket], dispatchDynamicMasks[bucket])
			match := node.block.NewValue2(node.block.Pos, OpEq64, f.Config.Types.Bool, pc, state)
			node.block.SetControl(match)
			if node.spec.decoy {
				node.block.Likely = BranchUnlikely
			} else {
				node.block.Likely = BranchUnknown
			}
		}
	}
	for i := range p.units {
		unit := &p.units[i]
		var computed []*Value
		if unit.count > 0 {
			computed = computedByBlock[handlers[i]]
			if computed == nil {
				var err error
				computed, err = vm3EmitUnit(handlers[i], p, unit, registers, pc, dispatchOpaqueZero, rng, encrypt)
				if err != nil {
					return err
				}
				computedByBlock[handlers[i]] = computed
			}
		}
		switch unit.kind {
		case vm2Branch:
			handlers[i].Reset(BlockIf)
			control := registers[unit.control]
			if computed != nil && computed[unit.control] != nil {
				control = computed[unit.control]
			}
			handlers[i].SetControl(control)
			handlers[i].Likely = BranchUnknown
		case vm2Return:
			handlers[i].Reset(BlockRet)
			result := handlers[i].NewValue0(unit.pos, OpMakeResult, unit.resultType)
			returnValue := registers[unit.returnReg]
			if computed != nil && computed[unit.returnReg] != nil {
				returnValue = computed[unit.returnReg]
			}
			result.AddArg(returnValue)
			result.AddArg(source.initMem)
			handlers[i].SetControl(result)
		}
	}

	// The old CFG is now unreachable from the original entry. Running the
	// normal dead-code pass here releases its values and blocks before lower.
	deadcode(f)
	return nil
}
