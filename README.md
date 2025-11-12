# mcfpass

A pure-Go password hashing and verification library supporting **MCF (Modular Crypt Format)** strings such as `$2y$...`, `$argon2id$...`, `$6$...`, `$5$...`, and `$1$...`.  

It allows Go applications to **verify, generate, and migrate** password hashes without requiring CGO or external libraries, making it ideal for authentication systems, control panels, or backend services that import users from **cPanel**, **Pure-FTPd**, or other UNIX-based environments.

---

##  Features

- Pure Go — **no CGO**, portable across platforms  
- Supports common MCF schemes:
  - `$2y$`, `$2a$`, `$2b$` → **bcrypt**
  - `$argon2id$`, `$argon2i$` → **Argon2**
  - `$6$` → **SHA-512-crypt**
  - `$5$` → **SHA-256-crypt**
  - `$1$` → **MD5-crypt** (legacy)
- Compatible with cPanel and Linux `/etc/shadow` formats  
- Secure re-hash migration policy (`NeedsRehash`)  
- Simple high-level API: `Hash`, `Verify`, `NeedsRehash`  
- Pure Go implementation using [`GehirnInc/crypt`](https://github.com/GehirnInc/crypt) and [`x/crypto`](https://pkg.go.dev/golang.org/x/crypto)

---

## Theoretical Background

The **Modular Crypt Format (MCF)** is a widely used convention for encoding password hashes with metadata.  
An MCF string begins with `$id$`, where the identifier determines the algorithm and format.  

Example breakdown:

```

$6$rounds=5000$saltstring$hashedvalue
↑  ↑                ↑            ↑
│  │                │            └─ encoded hash
│  │                └─ salt
│  └─ parameters (optional)
└─ algorithm ID (6 = SHA512-crypt)

````

| MCF Prefix | Algorithm        | Description / Typical Use                            |
|-------------|-----------------|------------------------------------------------------|
| `$2y$`, `$2b$` | bcrypt         | Adaptive key derivation, 72-byte password limit      |
| `$argon2id$`   | Argon2id       | Modern memory-hard KDF, recommended default          |
| `$6$`          | SHA512-crypt   | cPanel / Linux `/etc/shadow` default                 |
| `$5$`          | SHA256-crypt   | Alternate Linux scheme                               |
| `$1$`          | MD5-crypt      | Obsolete legacy hashes                               |

MCF enables **portable password verification** across systems and languages because all required parameters (algorithm, salt, iteration count) are embedded in the string.

---

## Installation

To install **mcfpass**, run:

```bash
go get github.com/pablolagos/mcfpass
```
Then import it into your project:

```go
import "github.com/pablolagos/mcfpass"
```

Requirements

- Go 1.23+
- No CGO required — works natively on Linux, macOS, and Windows.
- Tested with:
  - github.com/GehirnInc/crypt — pure-Go implementations of crypt(3)
  - golang.org/x/crypto — Argon2 and bcrypt support

## Usage

### Basic Example

```go
package main

import (
	"fmt"
	"github.com/pablolagos/mcfpass"
)

func main() {
	// Create a new password hash using Argon2id (default policy)
	policy := mcfpass.DefaultPolicy()
	hash, _ := mcfpass.Hash("MySecurePassword!", policy)

	fmt.Println("Hash:", hash)

	// Verify a user password
	ok, err := mcfpass.Verify("MySecurePassword!", hash)
	fmt.Println("Valid:", ok, "Error:", err)

	// Opportunistic migration (if using legacy hashes)
	if mcfpass.NeedsRehash("$6$salt$hash...", policy) {
		newHash, _ := mcfpass.Hash("MySecurePassword!", policy)
		fmt.Println("Migrated to Argon2id:", newHash)
	}
}
```

### Supported Algorithms

| Algorithm         | MCF Prefix             | Notes                                             |
| ----------------- | ---------------------- | ------------------------------------------------- |
| **bcrypt**        | `$2y$`, `$2a$`, `$2b$` | Cost factor from policy (`BcryptCost`)            |
| **Argon2id**      | `$argon2id$`           | Default; secure, memory-hard                      |
| **Argon2i**       | `$argon2i$`            | Legacy variant (less resistant to GPU attacks)    |
| **SHA-512-crypt** | `$6$`                  | Used by cPanel and modern Linux shadow files      |
| **SHA-256-crypt** | `$5$`                  | Alternative Linux hash                            |
| **MD5-crypt**     | `$1$`                  | Insecure; supported only for import/compatibility |

---

## Understanding the API

### `Verify(password, hash) (bool, error)`

Compares a plaintext password with an MCF hash.

```go
ok, err := mcfpass.Verify("secret", "$2y$12$abcdefgh...xyz")
```

* Returns `true` if password matches.
* Returns `(false, nil)` if the password is incorrect.
* Returns an error if the hash format is invalid or unsupported.

---

### `Hash(password, policy) (string, error)`

Generates a new MCF hash according to a given policy.

```go
p := mcfpass.DefaultPolicy() // Argon2id
hash, _ := mcfpass.Hash("secret", p)
```

#### Example bcrypt policy

```go
p := mcfpass.Policy{Algo: "bcrypt", BcryptCost: 13}
hash, _ := mcfpass.Hash("secret", p)
```

---

### `NeedsRehash(stored, policy) bool`

Determines whether an existing hash is outdated and should be upgraded to the current policy.

Typical use: **transparent rehashing** after a successful login.

```go
if mcfpass.NeedsRehash(storedHash, policy) {
	newHash, _ := mcfpass.Hash(password, policy)
	updateUserHashInDB(newHash)
}
```

---

## Recommended Usage Policy

For **new passwords**:

* Prefer **Argon2id** (default)
* Use at least 64 MiB memory and 2 iterations
* Use a 16-byte salt and 32-byte key length

For **imported users from cPanel or UNIX**:

* Store the original `$6$`, `$5$`, or `$1$` hash as is
* Verify using `mcfpass.Verify()` — the library auto-detects the scheme
* Optionally migrate to Argon2id on next successful login

---

## Integration Example 

Example verifying imported users:

```go
func authenticateUser(username, password string) bool {
	storedHash := getPasswordFromDB(username)
	ok, err := mcfpass.Verify(password, storedHash)
	if err != nil {
		log.Printf("auth error: %v", err)
		return false
	}
	if ok && mcfpass.NeedsRehash(storedHash, mcfpass.DefaultPolicy()) {
		newHash, _ := mcfpass.Hash(password, mcfpass.DefaultPolicy())
		updatePassword(username, newHash)
	}
	return ok
}
```

This design allows a seamless migration from legacy hashes while keeping modern accounts secure.

---

## Database Field Size Recommendations

When designing your user or authentication tables, it’s important to allocate the right amount of space for password hashes and related metadata.  
Different hashing algorithms produce strings of different lengths, but the **Modular Crypt Format (MCF)** used by `mcfpass` makes it easy to predict safe limits.

### Typical MCF Lengths

| Algorithm | Example Prefix | Typical Length (chars) | Notes |
|------------|----------------|------------------------|-------|
| `$2y$` / `$2b$` | bcrypt | ~60 | Always fixed-length |
| `$argon2id$` | Argon2id | 95–120 | Depends on memory/time parameters |
| `$6$` | SHA512-crypt | 90–106 | Common in cPanel and Linux `/etc/shadow` |
| `$5$` | SHA256-crypt | 70–86 | Slightly shorter than SHA512 |
| `$1$` | MD5-crypt | ~34 | Obsolete, legacy-only |

### Recommended Schema

| Database | Field Type | Recommended Size | Reason |
|-----------|-------------|------------------|--------|
| **SQLite** | `TEXT` | — | TEXT handles any reasonable MCF hash |
| **MySQL / MariaDB** | `VARCHAR(255)` | 255 | Future-proof for all MCF variants |
| **PostgreSQL** | `VARCHAR(255)` or `TEXT` | 255 | TEXT is fine; VARCHAR(255) for consistency |

> `VARCHAR(255)` safely covers all modern algorithms including Argon2id and future variants with longer parameter strings.

---

## Security Considerations

* Never store plaintext passwords — only the MCF string.
* Always use `crypto/rand` for salts (already handled internally).
* Avoid MD5-crypt and SHA-256-crypt for new users.
* Limit bcrypt cost to 12–14 to avoid excessive CPU use on login bursts.
* For Argon2id, prefer memory cost ≥ 64 MiB for backend systems.

---

## Why MCF Matters

MCF standardizes how hashes are stored and recognized:

| Example                                        | Description                  |
| ---------------------------------------------- | ---------------------------- |
| `$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>` | Argon2id modern hash         |
| `$2y$12$abcdefghijklmnopqrstuvwx$...`          | bcrypt with cost 12          |
| `$6$saltstring$hashedvalue`                    | SHA512-crypt (cPanel, Linux) |

This self-describing format ensures long-term compatibility across different systems and programming languages.

---

## License

MIT License — free for commercial and open-source use.

---

## 👤 Author

Developed by **Pablo Lagos**
For integration into the CorePanel, Pyxsoft, and related security systems.

---

> “Passwords may change, but formats should not. MCF keeps your authentication future-proof.”

