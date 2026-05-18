package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeSSHType(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ssh-ed25519", "ed25519"},
		{"ssh-rsa", "rsa"},
		{"ssh-dss", "dsa"},
		{"ecdsa-sha2-nistp256", "ecdsa"},
		{"ecdsa-sha2-nistp384", "ecdsa"},
		{"ecdsa-sha2-nistp521", "ecdsa"},
		{"sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa"},
		{"sk-ssh-ed25519@openssh.com", "sk-ed25519"},
		{"unrecognized-type", "unrecognized-type"},
	}

	for _, tc := range tests {
		got := normalizeSSHType(tc.in)
		if got != tc.want {
			t.Errorf("normalizeSSHType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSSHFingerprintFromBlob(t *testing.T) {
	// SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	// stdlib base64 (with padding stripped by our function): LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ
	got := sshFingerprintFromBlob([]byte("hello"))
	want := "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestShortSSHFingerprint(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"SHA256:abcdefghijklmnopqrstuvwxyz", "SHA256:abcdefghijkl"},
		{"SHA256:exactlytwelvechars", "SHA256:exactlytwelv"},
		{"SHA256:short", "SHA256:short"},
		{"notprefixed:abcdefghijklmnop", "notprefixed:abcdefghijklmnop"},
	}

	for _, tc := range tests {
		got := shortSSHFingerprint(tc.in)
		if got != tc.want {
			t.Errorf("shortSSHFingerprint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSSHAgentHasFingerprint(t *testing.T) {
	blob := []byte("a key payload of arbitrary bytes")
	b64 := base64.StdEncoding.EncodeToString(blob)
	want := sshFingerprintFromBlob(blob)

	agentOut := fmt.Sprintf("ssh-rsa AAAA-different user@a\nssh-ed25519 %s user@b\n", b64)

	if !sshAgentHasFingerprint([]byte(agentOut), want) {
		t.Errorf("expected to find %q in agent output", want)
	}

	if sshAgentHasFingerprint([]byte(agentOut), "SHA256:doesnotexist") {
		t.Errorf("did not expect to find bogus fingerprint")
	}

	if sshAgentHasFingerprint([]byte(""), want) {
		t.Errorf("did not expect match in empty agent output")
	}
}

func TestParseSSHPub(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519.pub")

	blob := []byte("opaque-pubkey-bytes")
	b64 := base64.StdEncoding.EncodeToString(blob)
	content := "ssh-ed25519 " + b64 + " user@example\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	k, err := parseSSHPub(path)
	if err != nil {
		t.Fatalf("parseSSHPub: %v", err)
	}

	if k.Type != "ed25519" {
		t.Errorf("type = %q, want ed25519", k.Type)
	}
	if k.Comment != "user@example" {
		t.Errorf("comment = %q, want user@example", k.Comment)
	}
	if k.Fingerprint != sshFingerprintFromBlob(blob) {
		t.Errorf("fingerprint = %q, want %q", k.Fingerprint, sshFingerprintFromBlob(blob))
	}
}

func TestParseSSHPubNoComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_rsa.pub")

	blob := []byte("rsa-pubkey-bytes-without-comment")
	b64 := base64.StdEncoding.EncodeToString(blob)
	content := "ssh-rsa " + b64 + "\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	k, err := parseSSHPub(path)
	if err != nil {
		t.Fatalf("parseSSHPub: %v", err)
	}

	if k.Type != "rsa" {
		t.Errorf("type = %q, want rsa", k.Type)
	}
	if k.Comment != "" {
		t.Errorf("comment = %q, want empty", k.Comment)
	}
}

func TestParseSSHPubMalformed(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name, content string
	}{
		{"empty file", ""},
		{"one-field line", "ssh-ed25519\n"},
		{"bad base64", "ssh-ed25519 !!!notbase64!!! user@example\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".pub")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}

			if _, err := parseSSHPub(path); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
