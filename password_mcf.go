package mcfpass

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	yescrypt "github.com/openwall/yescrypt-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUnknownMCF     = errors.New("unknown MCF id")
	ErrInvalidMCF     = errors.New("invalid MCF format")
	ErrUnsupportedMCF = errors.New("unsupported MCF on this build")
)

// Policy defines hashing defaults and rehash thresholds.
type Policy struct {
	// Preferred algorithm for new hashes: "argon2id" | "bcrypt"
	Algo string

	// Bcrypt parameters
	BcryptCost int // 12-14 is a good default for servers in 2025

	// Argon2id parameters
	ArgonTime    uint32 // iterations
	ArgonMemory  uint32 // KiB (e.g., 64*1024 for 64 MiB)
	ArgonThreads uint8  // parallelism
	ArgonSaltLen int    // bytes
	ArgonKeyLen  uint32 // bytes
}

// DefaultPolicy returns a sane default (argon2id).
func DefaultPolicy() Policy {
	return Policy{
		Algo:         "argon2id",
		BcryptCost:   12,
		ArgonTime:    2,
		ArgonMemory:  64 * 1024, // 64 MiB
		ArgonThreads: 1,
		ArgonSaltLen: 16,
		ArgonKeyLen:  32,
	}
}

// Verify checks a plaintext password against an MCF hash.
func Verify(password, mcf string) (bool, error) {
	if len(mcf) < 4 || mcf[0] != '$' {
		return false, ErrInvalidMCF
	}
	id := nextField(mcf[1:])
	switch id {
	case "2y", "2a", "2b":
		return verifyBcrypt(password, mcf)
	case "argon2id", "argon2i":
		return verifyArgon2(password, mcf)
	case "6", "5", "1":
		return verifyCryptFamily(password, mcf)
	case "y":
		return verifyYescrypt(password, mcf)
	default:
		return false, ErrUnknownMCF
	}
}

// SupportedMCF reports whether Verify can check a plaintext password against the
// given stored MCF hash without a rehash or reset. It inspects only the algorithm
// id, never the password, so callers (e.g. migration/import tooling) can classify
// credential compatibility up front. It does not validate the full structure of
// the hash; a true result means "this scheme is understood", not "this exact
// string is well-formed".
func SupportedMCF(mcf string) bool {
	if len(mcf) < 4 || mcf[0] != '$' {
		return false
	}
	switch nextField(mcf[1:]) {
	case "2y", "2a", "2b", "argon2id", "argon2i", "6", "5", "1", "y":
		return true
	default:
		return false
	}
}

// Hash generates a new hash using the provided policy.
func Hash(password string, p Policy) (string, error) {
	switch strings.ToLower(p.Algo) {
	case "bcrypt":
		if p.BcryptCost == 0 {
			p.BcryptCost = 12
		}
		b, err := bcrypt.GenerateFromPassword([]byte(password), p.BcryptCost)
		return string(b), err
	case "argon2id":
		if p.ArgonSaltLen == 0 || p.ArgonTime == 0 || p.ArgonMemory == 0 || p.ArgonKeyLen == 0 {
			p = DefaultPolicy()
		}
		return hashArgon2id(password, p), nil
	default:
		return "", fmt.Errorf("unsupported policy algo: %s", p.Algo)
	}
}

// NeedsRehash decides if a stored hash should be upgraded to current policy.
func NeedsRehash(stored string, p Policy) bool {
	if len(stored) < 4 || stored[0] != '$' {
		return true
	}
	id := nextField(stored[1:])
	switch id {
	case "argon2id":
		params, err := parseArgonMCF(stored)
		if err != nil {
			return true
		}
		// Rehash if any key parameter is weaker than policy.
		if params.time < p.ArgonTime || params.memory < p.ArgonMemory || params.threads < p.ArgonThreads {
			return true
		}
		return false
	case "argon2i":
		// Prefer argon2id over argon2i
		return true
	case "2y", "2a", "2b":
		if len(stored) < 6 {
			return true
		}
		costStr := stored[4:6]
		cost, _ := strconv.Atoi(costStr)
		if p.BcryptCost == 0 {
			p.BcryptCost = 12
		}
		return cost < p.BcryptCost
	case "6", "5", "1", "y":
		// crypt-family and yescrypt → prefer migration to argon2id/bcrypt
		return true
	default:
		return true
	}
}

// ---------- bcrypt ----------

func verifyBcrypt(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ---------- Argon2 (MCF) ----------

// Argon2 MCF example:
// $argon2id$v=19$m=65536,t=2,p=1$<base64salt>$<base64hash>
type argonParams struct {
	variant string
	version int
	memory  uint32
	time    uint32
	threads uint8
	saltB64 string
	hashB64 string
}

func verifyArgon2(password, mcf string) (bool, error) {
	ap, err := parseArgonMCF(mcf)
	if err != nil {
		return false, err
	}
	salt, hash, err := b64Decode(ap.saltB64, ap.hashB64)
	if err != nil {
		return false, err
	}
	var dk []byte
	switch ap.variant {
	case "argon2id":
		dk = argon2.IDKey([]byte(password), salt, ap.time, ap.memory, ap.threads, uint32(len(hash)))
	case "argon2i":
		dk = argon2.Key([]byte(password), salt, ap.time, ap.memory, ap.threads, uint32(len(hash)))
	default:
		return false, ErrUnsupportedMCF
	}
	if subtle.ConstantTimeCompare(dk, hash) == 1 {
		return true, nil
	}
	return false, nil
}

func hashArgon2id(password string, p Policy) string {
	salt := mustRandBytes(p.ArgonSaltLen)
	dk := argon2.IDKey([]byte(password), salt, p.ArgonTime, p.ArgonMemory, p.ArgonThreads, p.ArgonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		19, p.ArgonMemory, p.ArgonTime, p.ArgonThreads,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk))
}

func parseArgonMCF(mcf string) (argonParams, error) {
	// Expect 6 parts: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	parts := strings.Split(mcf, "$")
	if len(parts) != 6 {
		return argonParams{}, ErrInvalidMCF
	}
	ap := argonParams{variant: parts[1], version: 19}
	if strings.HasPrefix(parts[2], "v=") {
		if v, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v=")); err == nil {
			ap.version = v
		}
	}
	for _, kv := range strings.Split(parts[3], ",") {
		switch {
		case strings.HasPrefix(kv, "m="):
			val, _ := strconv.Atoi(strings.TrimPrefix(kv, "m="))
			ap.memory = uint32(val)
		case strings.HasPrefix(kv, "t="):
			val, _ := strconv.Atoi(strings.TrimPrefix(kv, "t="))
			ap.time = uint32(val)
		case strings.HasPrefix(kv, "p="):
			val, _ := strconv.Atoi(strings.TrimPrefix(kv, "p="))
			ap.threads = uint8(val)
		}
	}
	ap.saltB64 = parts[4]
	ap.hashB64 = parts[5]
	if ap.memory == 0 || ap.time == 0 || ap.threads == 0 {
		return argonParams{}, ErrInvalidMCF
	}
	return ap, nil
}

// ---------- crypt(3) family (pure Go) ----------

// verifyCryptFamily implements $6$ (sha512-crypt), $5$ (sha256-crypt), $1$ (md5-crypt)
// using the pure-Go "GehirnInc/crypt" library.
func verifyCryptFamily(password, mcf string) (bool, error) {
	var c crypt.Crypter
	switch {
	case strings.HasPrefix(mcf, "$6$"):
		c = sha512_crypt.New()
	case strings.HasPrefix(mcf, "$5$"):
		c = sha256_crypt.New()
	case strings.HasPrefix(mcf, "$1$"):
		c = md5_crypt.New()
	default:
		return false, ErrUnknownMCF
	}
	// Crypter.Verify compares "mcf" with the password; returns nil if match.
	if err := c.Verify(mcf, []byte(password)); err != nil {
		// crypt.ErrKeyMismatch indicates a valid check but wrong password.
		if errors.Is(err, crypt.ErrKeyMismatch) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ---------- yescrypt ----------

// verifyYescrypt implements $y$ (yescrypt) verification using the pure-Go
// "openwall/yescrypt-go" library. A yescrypt MCF has the shape
// "$y$<params>$<salt>$<hash>". We recompute the hash by passing the stored MCF
// back as the "setting" (yescrypt-go reads only the params+salt portion) and
// constant-time compare the full result against the stored value.
func verifyYescrypt(password, mcf string) (bool, error) {
	// Expect 5 parts: ["", "y", "<params>", "<salt>", "<hash>"].
	parts := strings.Split(mcf, "$")
	if len(parts) != 5 || parts[2] == "" || parts[3] == "" || parts[4] == "" {
		return false, ErrInvalidMCF
	}
	recomputed, err := yescrypt.Hash([]byte(password), []byte(mcf))
	if err != nil {
		// A decoding/parameter error means the stored hash is not a valid
		// yescrypt MCF, not a wrong password.
		return false, ErrInvalidMCF
	}
	if subtle.ConstantTimeCompare(recomputed, []byte(mcf)) == 1 {
		return true, nil
	}
	return false, nil
}

// ---------- helpers ----------

func nextField(s string) string {
	if i := strings.IndexByte(s, '$'); i >= 0 {
		return s[:i]
	}
	return s
}

func b64Decode(sSalt, sHash string) ([]byte, []byte, error) {
	sb, err := base64.StdEncoding.DecodeString(sSalt)
	if err != nil {
		return nil, nil, err
	}
	hb, err := base64.StdEncoding.DecodeString(sHash)
	if err != nil {
		return nil, nil, err
	}
	return sb, hb, nil
}

func mustRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read should never fail on Linux; panic is acceptable for helper.
		panic(err)
	}
	return b
}
