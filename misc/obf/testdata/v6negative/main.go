package main

//go:encrypt
//go:streamv6
func invalidTicketStringCompare() bool {
	s := "v6-negative-string-compare"
	return s == "v6-negative-string-compare"
}

func main() {
	if invalidTicketStringCompare() {
		panic("negative fixture unexpectedly ran")
	}
}
