package cmdauth

import "testing"

func TestFireAndReplay(t *testing.T) {
	a := New([]byte("secret"), 10)
	c := Command{ID: "c1", Subsystem: "ACS", Opcode: "NOOP", Args: map[string]string{"n": "1"}}
	tok := a.Mint(c, 100)
	st, _ := a.Fire(c, tok, 105)
	if st != "FIRED" {
		t.Fatal(st)
	}
	st, reason := a.Fire(c, tok, 106)
	if st != "REFUSED" || reason != "TOKEN_REPLAY" {
		t.Fatalf("%s %s", st, reason)
	}
}

func TestExpired(t *testing.T) {
	a := New([]byte("secret"), 10)
	c := Command{ID: "c1", Subsystem: "ACS", Opcode: "NOOP", Args: map[string]string{}}
	tok := a.Mint(c, 100)
	st, reason := a.Fire(c, tok, 200)
	if reason != "EXPIRED" {
		t.Fatalf("%s %s", st, reason)
	}
}
