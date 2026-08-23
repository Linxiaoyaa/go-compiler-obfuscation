package main

/*
#include <stdint.h>
*/
import "C"

//go:vm
//go:encrypt
func vmMix(rounds, seed uint64) uint64 {
	state := seed ^ 0x6a09e667f3bcc909
	for i := uint64(0); i < rounds; i++ {
		if i&1 == 0 {
			state = ((state + i) ^ 0x9e3779b97f4a7c15) * 3
		} else {
			state = ((state ^ i) + 0xd1b54a32d192ed03) * 5
		}
	}
	return state
}

//go:encrypt
//go:ephemeral
func ephemeralCheck() bool {
	s := "full-ephemeral-v3"
	return len(s) == 17 && s[0] == 'f' && s[5] == 'e' && s[16] == '3'
}

//go:encrypt
//go:stream
func streamCheck() bool {
	s := "full-stream-byte-v4"
	return len(s) == 19 && s[0] == 'f' && s[5] == 's' && s[18] == '4'
}

//go:encrypt
//go:streamv5
func leaseCheck() bool {
	s := "full-lease-token-v5"
	return len(s) == 19 && s[0] == 'f' && s[5] == 'l' && s[18] == '5'
}

//go:encrypt
func encryptedInput(input uint64) uint64 {
	return input ^ 0x243f6a8885a308d3
}

//export FullProtectVerify
func FullProtectVerify(input C.ulonglong) C.ulonglong {
	return C.ulonglong(vmMix(9, encryptedInput(uint64(input)))<<1 | 1)
}

func main() {
	if !ephemeralCheck() || !streamCheck() || !leaseCheck() || FullProtectVerify(C.ulonglong(7)) == 0 {
		panic(uint64(0))
	}
}
