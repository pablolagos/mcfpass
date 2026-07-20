package mcfpass

import (
	"strings"
	"testing"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()

	if p.Algo != "argon2id" {
		t.Errorf("Expected algo 'argon2id', got %s", p.Algo)
	}
	if p.BcryptCost != 12 {
		t.Errorf("Expected bcrypt cost 12, got %d", p.BcryptCost)
	}
	if p.ArgonTime != 2 {
		t.Errorf("Expected argon time 2, got %d", p.ArgonTime)
	}
	if p.ArgonMemory != 64*1024 {
		t.Errorf("Expected argon memory 65536, got %d", p.ArgonMemory)
	}
	if p.ArgonThreads != 1 {
		t.Errorf("Expected argon threads 1, got %d", p.ArgonThreads)
	}
	if p.ArgonSaltLen != 16 {
		t.Errorf("Expected argon salt len 16, got %d", p.ArgonSaltLen)
	}
	if p.ArgonKeyLen != 32 {
		t.Errorf("Expected argon key len 32, got %d", p.ArgonKeyLen)
	}
}

func TestHashArgon2id(t *testing.T) {
	password := "testpassword123"
	policy := DefaultPolicy()

	hash, err := Hash(password, policy)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Expected argon2id hash prefix, got %s", hash[:20])
	}

	// Verify the generated hash
	valid, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Generated hash should verify correctly")
	}

	// Wrong password should fail
	valid, err = Verify("wrongpassword", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestHashBcrypt(t *testing.T) {
	password := "testpassword123"
	policy := Policy{Algo: "bcrypt", BcryptCost: 10}

	hash, err := Hash(password, policy)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("Expected bcrypt hash prefix, got %s", hash[:20])
	}

	// Verify the generated hash
	valid, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Generated hash should verify correctly")
	}
}

func TestHashInvalidAlgo(t *testing.T) {
	password := "testpassword123"
	policy := Policy{Algo: "invalid"}

	_, err := Hash(password, policy)
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func TestVerifyBcrypt(t *testing.T) {
	// Generate real bcrypt hashes for testing
	password := "password"

	// Test with generated hash
	policy := Policy{Algo: "bcrypt", BcryptCost: 10}
	hash, _ := Hash(password, policy)

	valid, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Generated bcrypt hash should verify correctly")
	}

	// Test wrong password
	valid, err = Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestVerifyArgon2(t *testing.T) {
	// Generate a real Argon2id hash for testing
	password := "password"
	policy := DefaultPolicy()
	hash, _ := Hash(password, policy)

	valid, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Generated Argon2id hash should verify correctly")
	}

	// Test wrong password
	valid, err = Verify("wrong", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestVerifyCryptFamily(t *testing.T) {
	tests := []struct {
		password string
		hash     string
		expected bool
	}{
		{"password", "$6$rounds=5000$salt$hashedvalue", false}, // Invalid hash but valid format
		{"password", "$5$salt$hashedvalue", false},             // Invalid hash but valid format
		{"password", "$1$salt$hashedvalue", false},             // Invalid hash but valid format
	}

	for i, test := range tests {
		valid, err := Verify(test.password, test.hash)
		// These should not error due to format, but verify as false due to wrong hash
		if err != nil {
			t.Errorf("Test %d: Verify failed: %v", i, err)
		}
		if valid {
			t.Errorf("Test %d: Expected false for invalid hash, got true", i)
		}
	}
}

func TestSupportedMCF(t *testing.T) {
	supported := []string{
		"$2y$12$abcdefghijklmnopqrstuv",
		"$2a$10$abcdefghijklmnopqrstuv",
		"$argon2id$v=19$m=65536,t=2,p=1$salt$hash",
		"$argon2i$v=19$m=65536,t=2,p=1$salt$hash",
		"$6$salt$hash",
		"$5$salt$hash",
		"$1$salt$hash",
		"$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC",
	}
	for _, h := range supported {
		if !SupportedMCF(h) {
			t.Errorf("SupportedMCF(%q) = false, want true", h)
		}
	}
	unsupported := []string{
		"",
		"invalid",
		"$",
		"$md5$x",
		"plaintextpassword",
		"$2$x", // truncated / unknown
	}
	for _, h := range unsupported {
		if SupportedMCF(h) {
			t.Errorf("SupportedMCF(%q) = true, want false", h)
		}
	}
}

func TestVerifyYescrypt(t *testing.T) {
	// Known-good yescrypt vectors (from openwall/yescrypt-go's own examples).
	tests := []struct {
		password string
		hash     string
		expected bool
	}{
		{"openwall", "$y$j9T$AAt9R641xPvCI9nXw1HHW/$cuQRBMN3N/f8IcmVN.4YrZ1bHMOiLOoz9/XQMKV/v0A", true},
		{"pleaseletmein", "$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC", true},
		// Correct hash, wrong password.
		{"wrongpassword", "$y$j9T$AAt9R641xPvCI9nXw1HHW/$cuQRBMN3N/f8IcmVN.4YrZ1bHMOiLOoz9/XQMKV/v0A", false},
	}

	for i, test := range tests {
		valid, err := Verify(test.password, test.hash)
		if err != nil {
			t.Fatalf("Test %d: Verify failed: %v", i, err)
		}
		if valid != test.expected {
			t.Errorf("Test %d: expected %v, got %v (pw=%q)", i, test.expected, valid, test.password)
		}
	}
}

func TestVerifyYescryptMalformed(t *testing.T) {
	// Structurally invalid yescrypt strings must return an error, not a silent false.
	malformed := []string{
		"$y$salt$hash",   // only 4 fields (missing hash field)
		"$y$j9T$onlysalt", // missing final hash field
		"$y$j9T$$hash",    // empty salt field
	}
	for i, h := range malformed {
		if _, err := Verify("password", h); err == nil {
			t.Errorf("Test %d: expected error for malformed yescrypt %q", i, h)
		}
	}
}

func TestVerifyInvalidMCF(t *testing.T) {
	tests := []string{
		"",             // Empty
		"invalid",      // No $ prefix
		"$",            // Just $
		"$invalid",     // Unknown algorithm
		"$y$salt$hash", // yescrypt not supported
	}

	for i, hash := range tests {
		_, err := Verify("password", hash)
		if err == nil {
			t.Errorf("Test %d: Expected error for invalid MCF: %s", i, hash)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	policy := DefaultPolicy()

	// Test argon2id with same parameters (no rehash needed)
	argon2idHash := "$argon2id$v=19$m=65536,t=2,p=1$salt$hash"
	if NeedsRehash(argon2idHash, policy) {
		t.Error("Argon2id with same parameters should not need rehash")
	}

	// Test argon2id with weaker parameters
	weakArgon2id := "$argon2id$v=19$m=32768,t=1,p=1$salt$hash"
	if !NeedsRehash(weakArgon2id, policy) {
		t.Error("Weak argon2id should need rehash")
	}

	// Test argon2i (should rehash to argon2id)
	argon2iHash := "$argon2i$v=19$m=65536,t=2,p=1$salt$hash"
	if !NeedsRehash(argon2iHash, policy) {
		t.Error("Argon2i should need rehash to argon2id")
	}

	// Test bcrypt with lower cost
	lowCostBcrypt := "$2b$10$abcdefghijklmnopqrstuvwxABCDEF123456789"
	if !NeedsRehash(lowCostBcrypt, Policy{Algo: "bcrypt", BcryptCost: 12}) {
		t.Error("Bcrypt with lower cost should need rehash")
	}

	// Test bcrypt with same cost
	sameCostBcrypt := "$2b$12$abcdefghijklmnopqrstuvwxABCDEF123456789"
	if NeedsRehash(sameCostBcrypt, Policy{Algo: "bcrypt", BcryptCost: 12}) {
		t.Error("Bcrypt with same cost should not need rehash")
	}

	// Test legacy formats (should always rehash)
	legacyHashes := []string{
		"$6$salt$hash", // SHA512-crypt
		"$5$salt$hash", // SHA256-crypt
		"$1$salt$hash", // MD5-crypt
	}

	for _, hash := range legacyHashes {
		if !NeedsRehash(hash, policy) {
			t.Errorf("Legacy hash %s should need rehash", hash)
		}
	}

	// Test invalid formats (should rehash)
	invalidHashes := []string{
		"",
		"invalid",
		"$",
	}

	for _, hash := range invalidHashes {
		if !NeedsRehash(hash, policy) {
			t.Errorf("Invalid hash %s should need rehash", hash)
		}
	}
}

func TestParseArgonMCF(t *testing.T) {
	// Valid Argon2id MCF
	mcf := "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
	params, err := parseArgonMCF(mcf)
	if err != nil {
		t.Fatalf("parseArgonMCF failed: %v", err)
	}

	if params.variant != "argon2id" {
		t.Errorf("Expected variant 'argon2id', got %s", params.variant)
	}
	if params.version != 19 {
		t.Errorf("Expected version 19, got %d", params.version)
	}
	if params.memory != 65536 {
		t.Errorf("Expected memory 65536, got %d", params.memory)
	}
	if params.time != 2 {
		t.Errorf("Expected time 2, got %d", params.time)
	}
	if params.threads != 1 {
		t.Errorf("Expected threads 1, got %d", params.threads)
	}

	// Invalid MCF (not enough parts)
	invalidMCF := "$argon2id$v=19$m=65536"
	_, err = parseArgonMCF(invalidMCF)
	if err == nil {
		t.Error("Expected error for invalid MCF format")
	}

	// Invalid MCF (missing required params)
	invalidParamsMCF := "$argon2id$v=19$m=0,t=0,p=0$salt$hash"
	_, err = parseArgonMCF(invalidParamsMCF)
	if err == nil {
		t.Error("Expected error for missing required parameters")
	}
}

func TestNextField(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2y$cost$salt$hash", "2y"},
		{"argon2id$v=19$m=65536,t=2,p=1", "argon2id"},
		{"6$rounds=5000$salt", "6"},
		{"nospecial", "nospecial"},
		{"", ""},
	}

	for i, test := range tests {
		result := nextField(test.input)
		if result != test.expected {
			t.Errorf("Test %d: Expected %s, got %s", i, test.expected, result)
		}
	}
}

func TestB64Decode(t *testing.T) {
	// Valid base64 strings
	saltB64 := "c29tZXNhbHQ=" // "somesalt" in base64 (properly padded)
	hashB64 := "aGFzaA=="     // "hash" in base64

	salt, hash, err := b64Decode(saltB64, hashB64)
	if err != nil {
		t.Fatalf("b64Decode failed: %v", err)
	}

	if string(salt) != "somesalt" {
		t.Errorf("Expected 'somesalt', got %s", string(salt))
	}
	if string(hash) != "hash" {
		t.Errorf("Expected 'hash', got %s", string(hash))
	}

	// Test with simple valid strings
	salt, hash, err = b64Decode("cw==", "aA==") // "s" and "h"
	if err != nil {
		t.Errorf("Simple base64 strings should be valid: %v", err)
	}
	if string(salt) != "s" || string(hash) != "h" {
		t.Errorf("Expected 's' and 'h', got '%s' and '%s'", string(salt), string(hash))
	}
}

// Benchmark tests
func BenchmarkHashArgon2id(b *testing.B) {
	password := "testpassword123"
	policy := DefaultPolicy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(password, policy)
	}
}

func BenchmarkHashBcrypt(b *testing.B) {
	password := "testpassword123"
	policy := Policy{Algo: "bcrypt", BcryptCost: 12}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(password, policy)
	}
}

func BenchmarkVerifyArgon2id(b *testing.B) {
	password := "testpassword123"
	policy := DefaultPolicy()
	hash, _ := Hash(password, policy)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(password, hash)
	}
}

func BenchmarkVerifyBcrypt(b *testing.B) {
	password := "testpassword123"
	policy := Policy{Algo: "bcrypt", BcryptCost: 12}
	hash, _ := Hash(password, policy)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(password, hash)
	}
}
