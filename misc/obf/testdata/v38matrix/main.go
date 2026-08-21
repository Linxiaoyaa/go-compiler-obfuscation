package main

//go:vm
//go:encrypt
func vmCalc(n, seed uint64) uint64 {
	acc := seed
	for i := uint64(0); i < n; i++ {
		if i&1 == 0 {
			acc = ((acc + i) ^ 0x123456789abcdef0) * 3
		} else {
			acc = ((acc - i) ^ 0x0fedcba987654321) + 7
		}
	}
	return acc
}

//go:encrypt
//go:ephemeral
func secretCheck() bool {
	s := "v38-cross-platform-ephemeral"
	return len(s) == 28 && s[0] == 'v' && s[27] == 'l'
}

func main() {
	if !secretCheck() || vmCalc(7, 11) == 0 {
		panic("v38 matrix failure")
	}
}
