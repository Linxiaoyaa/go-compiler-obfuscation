package main

//go:encrypt
//go:stream
func invalidStringCompare() bool {
	s := "v4-negative-string-compare"
	return s == "v4-negative-string-compare"
}

func main() {
	if invalidStringCompare() {
		panic("negative fixture unexpectedly ran")
	}
}
