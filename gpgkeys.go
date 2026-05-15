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

type Key struct {
	KeyID       string
	Fingerprint string
	PrimaryUID  UID
	Expires     time.Time
	Secret      bool
	Revoked     bool
	Expired     bool
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
		case "sec":
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
	pendingFpr, pendingUID := false, false

	flush := func() {
		if cur != nil && cur.Fingerprint != "" {
			keys = append(keys, *cur)
		}
		cur = nil
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
			if len(fields) < 7 {
				continue
			}

			cur = &Key{
				KeyID:   fields[4],
				Expires: parseTimestamp(fields[6]),
				Revoked: fields[1] == "r",
				Expired: fields[1] == "e",
			}
			pendingFpr = true
			pendingUID = true

		case "fpr":
			if cur != nil && pendingFpr && len(fields) >= 10 {
				cur.Fingerprint = fields[9]
				cur.Secret = secret[fields[9]]
				pendingFpr = false
			}

		case "uid":
			if cur != nil && pendingUID && len(fields) >= 10 {
				cur.PrimaryUID = parseUID(fields[9])
				pendingUID = false
			}
		}
	}

	flush()
	return keys
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
