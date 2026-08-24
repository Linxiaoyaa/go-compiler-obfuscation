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

//go:encrypt
//go:stream
func streamCheck(last int) bool {
	s := "v4-stream-byte-check"
	return len(s) == 20 && s[0] == 'v' && s[last] == 'k'
}

//go:encrypt
//go:streamv5
func leaseStreamCheck(last int) bool {
	s := "v5-lease-stream-check"
	return len(s) == 21 && s[0] == 'v' && s[3] == 'l' && s[last] == 'k'
}

//go:encrypt
//go:streamv6
func ticketStreamCheck(last int) bool {
	s := "v6-ticket-stream-check"
	return len(s) == 22 && s[0] == 'v' && s[3] == 't' && s[last] == 'k'
}

func main() {
	if !secretCheck() || !streamCheck(19) || !leaseStreamCheck(20) || !ticketStreamCheck(21) || vmCalc(7, 11) == 0 {
		panic("v38 matrix failure")
	}
}
