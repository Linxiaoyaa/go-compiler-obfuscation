package main

//go:noinline
func nativeCall(v uint64) uint64 {
	return ((v ^ 0x7f4a7c159e3779b9) * 9) + 0x94d049bb133111eb
}

//go:noinline
//go:obf
//go:encrypt
func nativeBranch(a, b uint64) uint64 {
	if a < b {
		return nativeCall((a ^ 0x1020304050607080) + b)
	}
	if a&1 == 0 {
		return nativeCall((a + 0x0badf00ddeadbeef) ^ b)
	}
	return nativeCall((a - b) ^ 0x55aa55aa55aa55aa)
}

//go:noinline
//go:obf
//go:encrypt
func nativeLoopCall(n, seed uint64) uint64 {
	state := seed
	for i := uint64(0); i < n; i++ {
		if i&1 == 0 {
			state = nativeCall(state ^ i)
		} else {
			state = nativeCall(state + i)
		}
	}
	return state
}

var deferred uint64

//go:noinline
func recordDeferred(v uint64) {
	deferred ^= v
}

//go:noinline
//go:obf
//go:encrypt
func nativeDefer(v uint64) uint64 {
	defer recordDeferred(v)
	if v&1 == 0 {
		return v ^ 0x3141592653589793
	}
	return v + 0x2718281828459045
}

//go:noinline
//go:obf
func nativeBool(v uint64) bool {
	return v&1 == 0
}

//go:noinline
//go:obf
func nativeZeroArg() bool {
	return true
}

//go:noinline
//go:obf
//go:encrypt
func nativeSwitch(v uint64) uint64 {
	switch v & 7 {
	case 0:
		return v ^ 0x1020304050607080
	case 1:
		return v + 0x0badf00ddeadbeef
	case 2:
		return v * 3
	case 3:
		return v ^ 0x3141592653589793
	case 4:
		return v + 0x2718281828459045
	case 5:
		return v * 5
	case 6:
		return v ^ 0x55aa55aa55aa55aa
	default:
		return v + 0x94d049bb133111eb
	}
}

//go:noinline
//go:obf
//go:encrypt
func nativeMultiReturn(v uint64) (uint64, uint64) {
	if v&1 == 0 {
		return v ^ 0x243f6a8885a308d3, v + 0x13198a2e03707344
	}
	return v + 0xa4093822299f31d0, v ^ 0x082efa98ec4e6c89
}

//go:noinline
//go:obf
//go:encrypt
func nativeRecover(v uint64) (result uint64) {
	defer func() {
		if recover() != nil {
			result = v ^ 0xbb67ae8584caa73b
		}
	}()
	if v&1 != 0 {
		panic(v)
	}
	return v ^ 0x6a09e667f3bcc909
}

func referenceCall(v uint64) uint64 {
	return ((v ^ 0x7f4a7c159e3779b9) * 9) + 0x94d049bb133111eb
}

func referenceBranch(a, b uint64) uint64 {
	if a < b {
		return referenceCall((a ^ 0x1020304050607080) + b)
	}
	if a&1 == 0 {
		return referenceCall((a + 0x0badf00ddeadbeef) ^ b)
	}
	return referenceCall((a - b) ^ 0x55aa55aa55aa55aa)
}

func referenceLoop(n, seed uint64) uint64 {
	state := seed
	for i := uint64(0); i < n; i++ {
		if i&1 == 0 {
			state = referenceCall(state ^ i)
		} else {
			state = referenceCall(state + i)
		}
	}
	return state
}

func referenceSwitch(v uint64) uint64 {
	switch v & 7 {
	case 0:
		return v ^ 0x1020304050607080
	case 1:
		return v + 0x0badf00ddeadbeef
	case 2:
		return v * 3
	case 3:
		return v ^ 0x3141592653589793
	case 4:
		return v + 0x2718281828459045
	case 5:
		return v * 5
	case 6:
		return v ^ 0x55aa55aa55aa55aa
	default:
		return v + 0x94d049bb133111eb
	}
}

func main() {
	for _, pair := range [][2]uint64{{0, 0}, {1, 2}, {0x1122334455667788, 17}, {^uint64(0), 63}} {
		a, b := pair[0], pair[1]
		if nativeBool(a) != (a&1 == 0) || !nativeZeroArg() {
			panic("native return envelope mismatch")
		}
		if nativeBranch(a, b) != referenceBranch(a, b) {
			panic("native branch mismatch")
		}
		if nativeSwitch(a) != referenceSwitch(a) {
			panic("native switch mismatch")
		}
		left, right := nativeMultiReturn(a)
		if a&1 == 0 {
			if left != a^0x243f6a8885a308d3 || right != a+0x13198a2e03707344 {
				panic("native multi-return mismatch")
			}
		} else if left != a+0xa4093822299f31d0 || right != a^0x082efa98ec4e6c89 {
			panic("native multi-return mismatch")
		}
		recoverWant := a ^ 0x6a09e667f3bcc909
		if a&1 != 0 {
			recoverWant = a ^ 0xbb67ae8584caa73b
		}
		if nativeRecover(a) != recoverWant {
			panic("native recover mismatch")
		}
		for _, n := range []uint64{0, 1, 2, 7, 19} {
			if nativeLoopCall(n, b) != referenceLoop(n, b) {
				panic("native loop mismatch")
			}
		}
		before := deferred
		want := a + 0x2718281828459045
		if a&1 == 0 {
			want = a ^ 0x3141592653589793
		}
		if nativeDefer(a) != want || deferred != before^a {
			panic("native defer mismatch")
		}
	}
}
