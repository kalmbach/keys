package main

import (
	"testing"
)

func TestUnescapeColonField(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"no escapes", "plain ascii", "plain ascii"},
		{"empty", "", ""},
		{"single escape", `\x3a`, ":"},
		{"utf-8 two-byte", `Caf\xc3\xa9`, "Café"},
		{"escape mid-string", `back\x5cslash`, `back\slash`},
		{"escape at start", `\x41B`, "AB"},
		{"escape at end", `A\x42`, "AB"},
		{"invalid hex falls through", `bad\xZZend`, `bad\xZZend`},
		{"incomplete escape kept literal", `tail\x`, `tail\x`},
		{"three-char escape kept literal", `pad\x3`, `pad\x3`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unescapeColonField(tc.in)
			if got != tc.want {
				t.Errorf("unescapeColonField(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseUID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want UID
	}{
		{"full", "Alice Smith (work) <alice@example.com>", UID{Name: "Alice Smith", Comment: "work", Email: "alice@example.com"}},
		{"name and email", "Bob <bob@example.com>", UID{Name: "Bob", Email: "bob@example.com"}},
		{"name only", "Carol", UID{Name: "Carol"}},
		{"name and comment", "Dave (host)", UID{Name: "Dave", Comment: "host"}},
		{"escaped utf-8", `Caf\xc3\xa9 <cafe@example.com>`, UID{Name: "Café", Email: "cafe@example.com"}},
		{"empty", "", UID{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUID(tc.in)
			if got != tc.want {
				t.Errorf("parseUID(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAlgoDisplay(t *testing.T) {
	tests := []struct {
		name  string
		algo  int
		bits  int
		curve string
		want  string
	}{
		{"rsa 4096", 1, 4096, "", "rsa4096"},
		{"rsa 2048", 1, 2048, "", "rsa2048"},
		{"rsa-encrypt", 2, 3072, "", "rsa3072"},
		{"rsa-sign", 3, 2048, "", "rsa2048"},
		{"elgamal", 16, 4096, "", "elg4096"},
		{"dsa", 17, 2048, "", "dsa2048"},
		{"ecdh no curve", 18, 0, "", "ecdh"},
		{"ecdsa no curve", 19, 0, "", "ecdsa"},
		{"eddsa no curve", 22, 0, "", "eddsa"},
		{"curve overrides algo", 22, 256, "ed25519", "ed25519"},
		{"unknown algo", 99, 0, "", "algo99"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := algoDisplay(tc.algo, tc.bits, tc.curve)
			if got != tc.want {
				t.Errorf("algoDisplay(%d,%d,%q) = %q, want %q", tc.algo, tc.bits, tc.curve, got, tc.want)
			}
		})
	}
}

func TestValidityName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"u", "ultimate"},
		{"f", "full"},
		{"m", "marginal"},
		{"n", "never"},
		{"r", "revoked"},
		{"e", "expired"},
		{"i", "invalid"},
		{"d", "disabled"},
		{"q", "unknown"},
		{"o", "unknown"},
		{"", ""},
		{"x", ""},
	}

	for _, tc := range tests {
		got := validityName(tc.in)
		if got != tc.want {
			t.Errorf("validityName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractCaps(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"sc", "SC"},
		{"e", "E"},
		{"a", "A"},
		{"scESC", "SC"}, // uppercase ignored
		{"D", ""},       // disabled marker not part of caps
		{"sceaSCEA", "SCEA"},
		{"", ""},
	}

	for _, tc := range tests {
		got := extractCaps(tc.in)
		if got != tc.want {
			t.Errorf("extractCaps(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSecretInfo(t *testing.T) {
	const input = `sec:u:255:22:1234567890ABCDEF:1700000000:1800000000:::::scESC:::+:::ed25519:::0:
fpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:
ssb:u:255:22:FEDCBA0987654321:1700000000:1800000000:::::e:::>:000F1234ABCD::cv25519::
fpr:::::::::FEDCBA0987654321FEDCBA0987654321FEDCBA09:
`

	got := parseSecretInfo([]byte(input))
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}

	primary, ok := got["1234567890ABCDEF1234567890ABCDEF12345678"]
	if !ok {
		t.Fatalf("primary fingerprint not found")
	}
	if primary.cardSerial != "" {
		t.Errorf("primary cardSerial = %q, want empty", primary.cardSerial)
	}

	sub, ok := got["FEDCBA0987654321FEDCBA0987654321FEDCBA09"]
	if !ok {
		t.Fatalf("sub fingerprint not found")
	}
	if sub.cardSerial != "000F1234ABCD" {
		t.Errorf("sub cardSerial = %q, want 000F1234ABCD", sub.cardSerial)
	}
}

func TestParseKeyList(t *testing.T) {
	const input = `tru::1:1741000000:0:3:1:5
pub:u:255:22:1234567890ABCDEF:1700000000:1800000000::-:::scESC:::::ed25519:::0:
fpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:
uid:u::::1700000000::HASH::Alice <alice@example.com>::::::::::0:
sub:u:256:18:FEDCBA0987654321:1700000000:1800000000:::::e:::::cv25519::
fpr:::::::::FEDCBA0987654321FEDCBA0987654321FEDCBA09:
pub:r:2048:1:DEADBEEFCAFEBABE:1500000000:1600000000::-:::sc:::::rsa2048:::0:
fpr:::::::::DEADBEEFCAFEBABEDEADBEEFCAFEBABEDEADBEEF:
uid:r::::1500000000::HASH::Bob (old) <bob@example.com>::::::::::0:
`

	secret := map[string]secretInfo{
		"1234567890ABCDEF1234567890ABCDEF12345678": {},
		"FEDCBA0987654321FEDCBA0987654321FEDCBA09": {cardSerial: "000F1234ABCD"},
	}

	keys := parseKeyList([]byte(input), secret)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}

	k0 := keys[0]
	if k0.Primary.KeyID != "1234567890ABCDEF" {
		t.Errorf("k0 KeyID = %q", k0.Primary.KeyID)
	}
	if k0.Primary.Fingerprint != "1234567890ABCDEF1234567890ABCDEF12345678" {
		t.Errorf("k0 fpr = %q", k0.Primary.Fingerprint)
	}
	if k0.Primary.Algo != "ed25519" {
		t.Errorf("k0 algo = %q, want ed25519", k0.Primary.Algo)
	}
	if !k0.Primary.Secret {
		t.Errorf("k0 expected Secret=true")
	}
	if k0.Primary.CardSerial != "" {
		t.Errorf("k0 primary CardSerial = %q, want empty", k0.Primary.CardSerial)
	}
	if k0.Primary.Caps != "SC" {
		t.Errorf("k0 caps = %q, want SC", k0.Primary.Caps)
	}
	if k0.Validity != "ultimate" {
		t.Errorf("k0 validity = %q", k0.Validity)
	}
	if k0.PrimaryUID.Name != "Alice" || k0.PrimaryUID.Email != "alice@example.com" {
		t.Errorf("k0 UID = %+v", k0.PrimaryUID)
	}
	if len(k0.SubKeys) != 1 {
		t.Fatalf("k0 subkeys = %d, want 1", len(k0.SubKeys))
	}
	if k0.SubKeys[0].KeyID != "FEDCBA0987654321" {
		t.Errorf("k0 sub KeyID = %q", k0.SubKeys[0].KeyID)
	}
	if k0.SubKeys[0].Algo != "cv25519" {
		t.Errorf("k0 sub algo = %q", k0.SubKeys[0].Algo)
	}
	if k0.SubKeys[0].Caps != "E" {
		t.Errorf("k0 sub caps = %q, want E", k0.SubKeys[0].Caps)
	}
	if k0.SubKeys[0].CardSerial != "000F1234ABCD" {
		t.Errorf("k0 sub CardSerial = %q", k0.SubKeys[0].CardSerial)
	}
	if !k0.SubKeys[0].Secret {
		t.Errorf("k0 sub expected Secret=true (card serial present implies secret)")
	}

	k1 := keys[1]
	if k1.Primary.Fingerprint != "DEADBEEFCAFEBABEDEADBEEFCAFEBABEDEADBEEF" {
		t.Errorf("k1 fpr = %q", k1.Primary.Fingerprint)
	}
	if !k1.Primary.Revoked {
		t.Errorf("k1 expected Revoked=true")
	}
	if k1.Validity != "revoked" {
		t.Errorf("k1 validity = %q", k1.Validity)
	}
	if k1.Primary.Algo != "rsa2048" {
		t.Errorf("k1 algo = %q", k1.Primary.Algo)
	}
	if k1.PrimaryUID.Name != "Bob" || k1.PrimaryUID.Comment != "old" {
		t.Errorf("k1 UID = %+v", k1.PrimaryUID)
	}
	if k1.Primary.Secret {
		t.Errorf("k1 expected Secret=false")
	}
	if len(k1.SubKeys) != 0 {
		t.Errorf("k1 subkeys = %d, want 0", len(k1.SubKeys))
	}
}

func TestParseKeyListEmpty(t *testing.T) {
	keys := parseKeyList(nil, nil)
	if len(keys) != 0 {
		t.Errorf("got %d keys from empty input, want 0", len(keys))
	}
}
