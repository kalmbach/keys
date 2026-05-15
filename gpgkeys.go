package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type UID struct {
	Name    string
	Comment string
	Email   string
}

type SubKey struct {
	KeyID       string
	Fingerprint string
	Algo        string
	Created     time.Time
	Expires     time.Time
	Caps        string
	Secret      bool
	Revoked     bool
	Expired     bool
	Invalid     bool
	Disabled    bool
}

type Key struct {
	Primary    SubKey
	PrimaryUID UID
	Validity   string
	SubKeys    []SubKey
}

func LoadKeys() ([]Key, error) {
	secret, err := loadSecretFingerprints()
	if err != nil {
		return nil, err
	}

	out, err := runGPG("--with-colons", "--list-keys")
	if err != nil {
		return nil, err
	}

	return parseKeyList(out, secret), nil
}

func loadSecretFingerprints() (map[string]bool, error) {
	out, err := runGPG("--with-colons", "--list-secret-keys")
	if err != nil {
		return nil, err
	}

	set := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	pending := false

	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "sec", "ssb":
			pending = true

		case "fpr":
			if pending && len(fields) >= 10 {
				set[fields[9]] = true
				pending = false
			}
		}
	}

	return set, sc.Err()
}

func parseKeyList(out []byte, secret map[string]bool) []Key {
	var keys []Key
	var cur *Key
	var pendingSub *SubKey
	pendingPrimaryFpr, pendingUID := false, false

	flush := func() {
		if cur != nil && cur.Primary.Fingerprint != "" {
			keys = append(keys, *cur)
		}
		cur = nil
		pendingSub = nil
		pendingPrimaryFpr = false
		pendingUID = false
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "pub":
			flush()
			if len(fields) < 12 {
				continue
			}

			cur = &Key{
				Primary: SubKey{
					KeyID:    fields[4],
					Created:  parseTimestamp(fields[5]),
					Expires:  parseTimestamp(fields[6]),
					Algo:     algoDisplay(atoi(fields[3]), atoi(fields[2]), colonField(fields, 16)),
					Caps:     extractCaps(fields[11]),
					Revoked:  fields[1] == "r",
					Expired:  fields[1] == "e",
					Invalid:  fields[1] == "i",
					Disabled: strings.ContainsRune(fields[11], 'D'),
				},
			}
			pendingPrimaryFpr = true
			pendingUID = true

		case "sub":
			if cur == nil || len(fields) < 12 {
				continue
			}

			cur.SubKeys = append(cur.SubKeys, SubKey{
				KeyID:    fields[4],
				Created:  parseTimestamp(fields[5]),
				Expires:  parseTimestamp(fields[6]),
				Algo:     algoDisplay(atoi(fields[3]), atoi(fields[2]), colonField(fields, 16)),
				Caps:     extractCaps(fields[11]),
				Revoked:  fields[1] == "r",
				Expired:  fields[1] == "e",
				Invalid:  fields[1] == "i",
				Disabled: strings.ContainsRune(fields[11], 'D'),
			})
			pendingSub = &cur.SubKeys[len(cur.SubKeys)-1]

		case "fpr":
			if cur == nil || len(fields) < 10 {
				continue
			}

			fpr := fields[9]
			if pendingPrimaryFpr {
				cur.Primary.Fingerprint = fpr
				cur.Primary.Secret = secret[fpr]
				pendingPrimaryFpr = false

			} else if pendingSub != nil {
				pendingSub.Fingerprint = fpr
				pendingSub.Secret = secret[fpr]
				pendingSub = nil
			}

		case "uid":
			if cur == nil || !pendingUID || len(fields) < 10 {
				continue
			}

			cur.PrimaryUID = parseUID(fields[9])
			cur.Validity = validityName(fields[1])
			pendingUID = false
		}
	}

	flush()
	return keys
}

func colonField(fields []string, idx int) string {
	if idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func algoDisplay(algoNum, bits int, curve string) string {
	if curve != "" {
		return curve
	}

	switch algoNum {
	case 1, 2, 3:
		return fmt.Sprintf("rsa%d", bits)

	case 16:
		return fmt.Sprintf("elg%d", bits)

	case 17:
		return fmt.Sprintf("dsa%d", bits)

	case 18:
		return "ecdh"

	case 19:
		return "ecdsa"

	case 22:
		return "eddsa"

	default:
		return fmt.Sprintf("algo%d", algoNum)
	}
}

func extractCaps(field string) string {
	var b strings.Builder
	for _, c := range field {
		if c >= 'a' && c <= 'z' {
			b.WriteRune(c - 'a' + 'A')
		}
	}
	return b.String()
}

func validityName(letter string) string {
	switch letter {
	case "u":
		return "ultimate"

	case "f":
		return "full"

	case "m":
		return "marginal"

	case "n":
		return "never"

	case "r":
		return "revoked"

	case "e":
		return "expired"

	case "i":
		return "invalid"

	case "d":
		return "disabled"

	case "q", "o":
		return "unknown"
	}

	return ""
}

func runGPG(args ...string) ([]byte, error) {
	out, err := exec.Command("gpg", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("gpg: %s", strings.TrimSpace(string(ee.Stderr)))
		}

		return nil, err
	}

	return out, nil
}

func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0)
	}

	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}

	return time.Time{}
}

func parseUID(raw string) UID {
	s := unescapeColonField(raw)
	var uid UID

	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			uid.Email = s[i+1 : j]
			s = strings.TrimSpace(s[:i])
		}
	}

	if i := strings.LastIndex(s, "("); i >= 0 {
		if j := strings.LastIndex(s, ")"); j > i {
			uid.Comment = s[i+1 : j]
			s = strings.TrimSpace(s[:i])
		}
	}

	uid.Name = s
	return uid
}

func unescapeColonField(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}

		b.WriteByte(s[i])
	}

	return b.String()
}
