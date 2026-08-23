package main

//go:encrypt
//go:streamv5
func invalidLeaseStringCompare() bool {
	s := "v5-negative-string-compare"
	return s == "v5-negative-string-compare"
}

func main() {
	if invalidLeaseStringCompare() {
		panic("negative fixture unexpectedly ran")
	}
}
