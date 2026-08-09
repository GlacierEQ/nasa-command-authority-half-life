package cmdauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

type Command struct {
	ID, Subsystem, Opcode string
	Args                  map[string]string
}

type Token struct {
	ID, CmdDigest string
	NotBefore, NotAfter float64
	MAC string
}

type Authority struct {
	secret   []byte
	halfLife float64
	used     map[string]struct{}
	mu       sync.Mutex
	seq      int
}

func New(secret []byte, halfLife float64) *Authority {
	return &Authority{secret: secret, halfLife: halfLife, used: map[string]struct{}{}}
}

func (a *Authority) Digest(c Command) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%v", c.ID, c.Subsystem, c.Opcode, c.Args)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Authority) Mint(c Command, now float64) Token {
	a.mu.Lock()
	a.seq++
	id := fmt.Sprintf("tok-%d", a.seq)
	a.mu.Unlock()
	cd := a.Digest(c)
	nb, na := now, now+a.halfLife
	mac := a.mac(id, cd, nb, na)
	return Token{ID: id, CmdDigest: cd, NotBefore: nb, NotAfter: na, MAC: mac}
}

func (a *Authority) mac(id, cd string, nb, na float64) string {
	m := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(m, "%s|%s|%v|%v", id, cd, nb, na)
	return hex.EncodeToString(m.Sum(nil))
}

func (a *Authority) Fire(c Command, tok Token, now float64) (string, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.used[tok.ID]; ok {
		return "REFUSED", "TOKEN_REPLAY"
	}
	if a.mac(tok.ID, tok.CmdDigest, tok.NotBefore, tok.NotAfter) != tok.MAC {
		return "REFUSED", "BAD_MAC"
	}
	if a.Digest(c) != tok.CmdDigest {
		return "REFUSED", "COMMAND_MISMATCH"
	}
	if now < tok.NotBefore || now > tok.NotAfter {
		return "REFUSED", "EXPIRED"
	}
	a.used[tok.ID] = struct{}{}
	return "FIRED", ""
}
