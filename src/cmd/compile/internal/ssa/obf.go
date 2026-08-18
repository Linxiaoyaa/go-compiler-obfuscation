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

const protectionPragmas = ir.ProtectObfuscate | ir.ProtectEncrypt | ir.ProtectVirtualize

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
	h := fnv.New64a()
	_, _ = h.Write([]byte(base.Debug.ObfSeed))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(protectionFunctionName(f)))
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
	if flags&ir.ProtectExclude != 0 {
		names = append(names, "noprotect")
	}
	return strings.Join(names, ",")
}

func reportProtection(f *Func, flags ir.ProtectionFlag, applied string) {
	if base.Debug.ObfReport == 0 {
		return
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

	program, err := buildVM2Program(f)
	if err != nil {
		protectionError(f, "vm", "%v", err)
		return
	}
	if err := installVM2Program(f, program, flags&ir.ProtectEncrypt != 0); err != nil {
		protectionError(f, "vm", "%v", err)
		return
	}

	applied := fmt.Sprintf("vm=register-threaded-v2 instructions=%d registers=%d blocks=%d branches=%d checks=%d decoys=%d",
		len(program.instructions), len(program.registers), len(program.blocks), program.branches, program.checks, program.decoys)
	if flags&ir.ProtectEncrypt != 0 {
		applied += " encrypt=const64-state-v2"
	}
	applied += " dispatch=random-checks-v1"
	if flags&ir.ProtectObfuscate != 0 {
		applied += " obf=vm-dispatch-v2"
	}
	reportProtection(f, flags, applied)
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
				if !stringProtected {
					protectionError(f, "encrypt", "%v", err)
					return
				}
				n, err = encodeGeneralUint64Constants(f, rng)
				if err != nil {
					protectionError(f, "encrypt", "%v", err)
					return
				}
				applied = append(applied, fmt.Sprintf("encrypt=const64-general-v1(%d)", n))
			} else {
				applied = append(applied, fmt.Sprintf("encrypt=const64-v1(%d)", n))
			}
		}
		if stringProtected {
			applied = append(applied, "encrypt=str-runtime-v1")
		}
	}
	if flags&ir.ProtectObfuscate != 0 {
		if err := insertOpaqueDiamond(f, rng); err != nil {
			protectionError(f, "obf", "%v", err)
			return
		}
		applied = append(applied, "obf=bcf-v1")
	}
	reportProtection(f, flags, strings.Join(applied, " "))
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
			if ok && aux.Fn != nil && strings.Contains(aux.Fn.Name, "runtime.obfStringData") {
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
			if !ok || aux.Fn == nil || !strings.Contains(aux.Fn.Name, "runtime.obfStringData") {
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
	checks       int
	decoys       int
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

type vm2DispatchKind uint8

const (
	vm2InitialEdge vm2DispatchKind = iota
	vm2ExecEdge
	vm2MoveEdge
	vm2InvalidEdge
)

type vm2DispatchInfo struct {
	kind  vm2DispatchKind
	inst  *vm2Instruction
	moves []vm2Move
	next  int
}

func vm2StateConstant(b *Block, source *Value, pos src.XPos, value uint64, rng *protectionRNG, encrypt bool) *Value {
	if !encrypt {
		return b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(value))
	}
	mask := rng.next()
	if mask == 0 {
		mask = 0x9e3779b97f4a7c15
	}
	encoded := b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(value^mask))
	key := b.NewValue0I(pos, OpConst64, b.Func.Config.Types.UInt64, int64(mask))
	if source == nil {
		return b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, encoded, key)
	}
	zero := opaqueZero64(b, source)
	dynamicKey := b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, key, zero)
	return b.NewValue2(pos, OpXor64, b.Func.Config.Types.UInt64, encoded, dynamicKey)
}

func vm2ValueConstant(b *Block, source *Value, pos src.XPos, value uint64, rng *protectionRNG, encrypt bool) *Value {
	return vm2StateConstant(b, source, pos, value, rng, encrypt)
}

func vm2EmitValue(b *Block, inst *vm2Instruction, regs []*Value, pc *Value, rng *protectionRNG, encrypt bool) (*Value, error) {
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
		return vm2ValueConstant(b, pc, v.Pos, inst.imm, rng, encrypt), nil
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

func installVM2Program(f *Func, p *vm2Program, encrypt bool) error {
	if len(p.instructions) == 0 || p.initMem == nil || p.sourceArg == nil {
		return fmt.Errorf("invalid v2 VM program")
	}
	entry := f.Entry
	for len(entry.Succs) != 0 {
		entry.removeEdge(0)
	}
	entry.Reset(BlockPlain)
	entry.Likely = BranchUnknown

	rng := newProtectionRNG(f)
	states := make([]uint64, len(p.instructions)+1)
	seen := make(map[uint64]bool, len(states))
	for i := range states {
		for {
			s := rng.next()
			if s != 0 && !seen[s] {
				states[i] = s
				seen[s] = true
				break
			}
		}
	}
	invalidState := states[len(states)-1]
	checkOrder := vm2CheckPermutation(len(p.instructions), rng)
	decoyCount := (len(p.instructions) + 1) / 2
	if decoyCount > 128 {
		decoyCount = 128
	}
	decoyStates := make([]uint64, decoyCount)
	for i := range decoyStates {
		for {
			state := rng.next()
			if state != 0 && !seen[state] {
				decoyStates[i] = state
				seen[state] = true
				break
			}
		}
	}
	p.checks = len(p.instructions) + decoyCount
	p.decoys = decoyCount

	dispatch := f.NewBlock(BlockPlain)
	checks := make([]*Block, len(p.instructions))
	handlers := make([]*Block, len(p.instructions))
	for i, inst := range p.instructions {
		checks[i] = f.NewBlock(BlockIf)
		handlers[i] = f.NewBlock(BlockPlain)
		checks[i].Pos = inst.pos
		handlers[i].Pos = inst.pos
	}
	decoys := make([]*Block, decoyCount)
	for i := range decoys {
		decoys[i] = f.NewBlock(BlockIf)
		decoys[i].Pos = entry.Pos
	}
	invalid := f.NewBlock(BlockPlain)
	dispatch.Pos = entry.Pos
	invalid.Pos = entry.Pos

	entry.AddEdgeTo(dispatch)
	checkChain := make([]*Block, 0, len(checks)+len(decoys))
	for _, index := range checkOrder {
		checkChain = append(checkChain, checks[index])
	}
	checkChain = append(checkChain, decoys...)
	dispatch.AddEdgeTo(checkChain[0])
	infos := make(map[*Block]vm2DispatchInfo, len(p.instructions)*2+2)
	infos[entry] = vm2DispatchInfo{kind: vm2InitialEdge, next: 0}
	for i, inst := range p.instructions {
		checks[i].AddEdgeTo(handlers[i])
		switch inst.kind {
		case vm2Exec:
			handlers[i].AddEdgeTo(dispatch)
			infos[handlers[i]] = vm2DispatchInfo{kind: vm2ExecEdge, inst: &p.instructions[i], next: inst.next}
		case vm2Jump:
			handlers[i].AddEdgeTo(dispatch)
			infos[handlers[i]] = vm2DispatchInfo{kind: vm2MoveEdge, moves: inst.edges[0].moves, next: inst.edges[0].target}
		case vm2Branch:
			thenBlock := f.NewBlock(BlockPlain)
			elseBlock := f.NewBlock(BlockPlain)
			thenBlock.Pos = inst.pos
			elseBlock.Pos = inst.pos
			handlers[i].AddEdgeTo(thenBlock)
			handlers[i].AddEdgeTo(elseBlock)
			thenBlock.AddEdgeTo(dispatch)
			elseBlock.AddEdgeTo(dispatch)
			infos[thenBlock] = vm2DispatchInfo{kind: vm2MoveEdge, moves: inst.edges[0].moves, next: inst.edges[0].target}
			infos[elseBlock] = vm2DispatchInfo{kind: vm2MoveEdge, moves: inst.edges[1].moves, next: inst.edges[1].target}
		case vm2Return:
			// The handler is converted to BlockRet after the dispatcher Phis
			// have been created below.
		default:
			return fmt.Errorf("invalid v2 instruction kind %d", inst.kind)
		}
	}
	for i, decoy := range decoys {
		decoy.AddEdgeTo(invalid)
		_ = i
	}
	for i, check := range checkChain {
		if i+1 < len(checkChain) {
			check.AddEdgeTo(checkChain[i+1])
		} else {
			check.AddEdgeTo(invalid)
		}
	}
	invalid.AddEdgeTo(dispatch)
	infos[invalid] = vm2DispatchInfo{kind: vm2InvalidEdge, next: -1}

	uint64Type := f.Config.Types.UInt64
	pc := dispatch.NewValue0(entry.Pos, OpPhi, uint64Type)
	registers := make([]*Value, len(p.registers))
	for i, v := range p.registers {
		registers[i] = dispatch.NewValue0(v.Pos, OpPhi, v.Type)
	}
	zero64 := entry.NewValue0I(entry.Pos, OpConst64, uint64Type, 0)
	zeroBool := entry.NewValue0I(entry.Pos, OpConstBool, f.Config.Types.Bool, 0)

	// Every edge into dispatch contributes one state and a complete register
	// snapshot.  Unchanged registers deliberately use their dispatcher Phi as
	// the argument; this preserves the old iteration's value across loops.
	for _, edge := range dispatch.Preds {
		info, ok := infos[edge.b]
		if !ok {
			return fmt.Errorf("missing dispatcher metadata for %v", edge.b)
		}
		var state *Value
		switch info.kind {
		case vm2InitialEdge:
			state = vm2StateConstant(entry, p.sourceArg, entry.Pos, states[0], rng, encrypt)
		case vm2InvalidEdge:
			state = vm2StateConstant(edge.b, pc, edge.b.Pos, invalidState, rng, encrypt)
		default:
			if info.next < 0 || info.next >= len(states)-1 {
				return fmt.Errorf("invalid dispatcher target %d", info.next)
			}
			state = vm2StateConstant(edge.b, pc, edge.b.Pos, states[info.next], rng, encrypt)
		}
		pc.AddArg(state)

		var computed *Value
		if info.kind == vm2ExecEdge {
			var err error
			computed, err = vm2EmitValue(edge.b, info.inst, registers, pc, rng, encrypt)
			if err != nil {
				return err
			}
		}
		moveByDst := make(map[int]int, len(info.moves))
		for _, move := range info.moves {
			moveByDst[move.dst] = move.src
		}
		for i, phi := range registers {
			var value *Value
			switch {
			case info.kind == vm2InitialEdge:
				value = vm2InitialRegisterValue(entry, p.registers[i], zero64, zeroBool)
			case info.kind == vm2ExecEdge && i == info.inst.dst:
				value = computed
			default:
				if srcReg, ok := moveByDst[i]; ok {
					value = registers[srcReg]
				} else {
					value = phi
				}
			}
			phi.AddArg(value)
		}
	}

	for i, check := range checks {
		pos := p.instructions[i].pos
		state := vm2StateConstant(check, pc, pos, states[i], rng, encrypt)
		match := check.NewValue2(pos, OpEq64, f.Config.Types.Bool, pc, state)
		check.SetControl(match)
		check.Likely = BranchLikely
	}
	for i, decoy := range decoys {
		state := vm2StateConstant(decoy, pc, decoy.Pos, decoyStates[i], rng, encrypt)
		match := decoy.NewValue2(decoy.Pos, OpEq64, f.Config.Types.Bool, pc, state)
		decoy.SetControl(match)
		decoy.Likely = BranchUnlikely
	}
	for i, inst := range p.instructions {
		switch inst.kind {
		case vm2Branch:
			handlers[i].Reset(BlockIf)
			handlers[i].SetControl(registers[inst.control])
			handlers[i].Likely = BranchUnknown
		case vm2Return:
			handlers[i].Reset(BlockRet)
			result := handlers[i].NewValue0(inst.pos, OpMakeResult, inst.resultType)
			result.AddArg(registers[inst.returnReg])
			result.AddArg(p.initMem)
			handlers[i].SetControl(result)
		}
	}

	// The old CFG is now unreachable from the original entry.  Running the
	// normal dead-code pass here releases its values and blocks before lower.
	deadcode(f)
	return nil
}
