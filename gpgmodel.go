package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

type gpgMode int

const (
	gpgModeIdle gpgMode = iota
	gpgModeExpire
	gpgModeDetails
	gpgModeGenerate
	gpgModeDeleteConfirm
)

type gpgGenStep int

const (
	gpgGenStepUID gpgGenStep = iota
	gpgGenStepAlgo
	gpgGenStepExpiry
)

var gpgGenAlgoOptions = []string{"default", "rsa4096", "rsa3072"}

type gpgExpireDoneMsg struct{ err error }

type gpgPassphraseDoneMsg struct{ err error }

type gpgGenerateDoneMsg struct{ err error }

type gpgDeleteDoneMsg struct {
	keyID string
	err   error
}

type gpgYankDoneMsg struct {
	keyID string
	err   error
}

type gpgKeysReloadedMsg struct {
	keys []Key
	err  error
}

type gpgNavItem struct {
	keyIdx int
	subIdx int // -1 for primary
}

type gpgModel struct {
	keys    []Key
	cursor  int
	mode    gpgMode
	input   string
	status  string
	err     error
	genStep gpgGenStep
	genUID  string
	genAlgo int
}

func (g gpgModel) idle() bool {
	return g.mode == gpgModeIdle
}

func (g gpgModel) navItems() []gpgNavItem {
	var items []gpgNavItem
	for i, k := range g.keys {
		items = append(items, gpgNavItem{keyIdx: i, subIdx: -1})
		for j := range k.SubKeys {
			items = append(items, gpgNavItem{keyIdx: i, subIdx: j})
		}
	}
	return items
}

func (g gpgModel) currentSubKey() (Key, SubKey, bool) {
	items := g.navItems()

	if g.cursor < 0 || g.cursor >= len(items) {
		return Key{}, SubKey{}, false
	}

	item := items[g.cursor]
	k := g.keys[item.keyIdx]

	if item.subIdx < 0 {
		return k, k.Primary, true
	}

	return k, k.SubKeys[item.subIdx], true
}

func (g gpgModel) onPrimary() bool {
	items := g.navItems()

	if g.cursor < 0 || g.cursor >= len(items) {
		return false
	}

	return items[g.cursor].subIdx < 0
}

func (g gpgModel) update(msg tea.Msg) (gpgModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch g.mode {
		case gpgModeExpire:
			return g.updateExpire(msg)

		case gpgModeDetails:
			return g.updateDetails(msg)

		case gpgModeGenerate:
			return g.updateGenerate(msg)

		case gpgModeDeleteConfirm:
			return g.updateDeleteConfirm(msg)
		}

		return g.updateIdle(msg)

	case gpgExpireDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			g.status = "expiry updated"
		}

		return g, reloadGPGKeysCmd

	case gpgPassphraseDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			g.status = "passphrase changed"
		}

		return g, nil

	case gpgGenerateDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			g.status = "key generated"
		}

		return g, reloadGPGKeysCmd

	case gpgDeleteDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			g.status = fmt.Sprintf("deleted %s", msg.keyID)
		}

		return g, reloadGPGKeysCmd

	case gpgYankDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("yank error: %v", msg.err)
		} else {
			g.status = fmt.Sprintf("copied %s", msg.keyID)
		}

		return g, nil

	case gpgKeysReloadedMsg:
		g.keys = msg.keys
		g.err = msg.err

		n := len(g.navItems())
		if g.cursor >= n {
			g.cursor = n - 1
		}

		if g.cursor < 0 {
			g.cursor = 0
		}

		return g, nil
	}

	return g, nil
}

func (g gpgModel) updateIdle(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	items := g.navItems()

	switch msg.String() {
	case "up", "k":
		if g.err == nil && g.cursor > 0 {
			g.cursor--
		}

	case "down", "j":
		if g.err == nil && g.cursor < len(items)-1 {
			g.cursor++
		}

	case "e":
		if g.err == nil && len(items) > 0 {
			k, sk, ok := g.currentSubKey()
			if !ok {
				return g, nil
			}

			if !k.Primary.Secret {
				g.status = "can't edit expiry: no secret key for primary"
				return g, nil
			}

			if !g.onPrimary() && !sk.Secret {
				g.status = "can't edit expiry: subkey secret material not available"
				return g, nil
			}

			g.mode = gpgModeExpire
			g.input = ""
			g.status = ""
		}

	case "p":
		if g.err == nil && len(items) > 0 {
			k, _, ok := g.currentSubKey()
			if !ok {
				return g, nil
			}

			if !k.Primary.Secret {
				g.status = "can't change passphrase: no secret key"
				return g, nil
			}

			g.status = ""
			return g, passphraseCmd(k.Primary.Fingerprint)
		}

	case "enter":
		if g.err == nil && len(items) > 0 {
			g.mode = gpgModeDetails
			g.status = ""
		}

	case "g":
		if g.err == nil {
			g.mode = gpgModeGenerate
			g.genStep = gpgGenStepUID
			g.genUID = ""
			g.genAlgo = 0
			g.input = ""
			g.status = ""
		}

	case "d":
		if g.err == nil && len(items) > 0 {
			if !g.onPrimary() {
				g.status = "delete: select pub row (subkey delete not supported)"
				return g, nil
			}

			g.mode = gpgModeDeleteConfirm
			g.status = ""
		}

	case "y":
		if g.err == nil && len(items) > 0 {
			k, _, ok := g.currentSubKey()
			if !ok {
				return g, nil
			}

			g.status = ""
			return g, yankGPGCmd(k.Primary.Fingerprint, k.Primary.KeyID)
		}
	}

	return g, nil
}

func (g gpgModel) updateDetails(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q":
		g.mode = gpgModeIdle
	}

	return g, nil
}

func (g gpgModel) updateDeleteConfirm(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	k, _, ok := g.currentSubKey()
	if !ok {
		g.mode = gpgModeIdle
		return g, nil
	}

	if s := msg.String(); s == "y" || s == "Y" {
		g.mode = gpgModeIdle
		return g, deleteGPGKeyCmd(k.Primary.Fingerprint, k.Primary.KeyID, k.Primary.Secret)
	}

	g.mode = gpgModeIdle
	return g, nil
}

func (g gpgModel) updateGenerate(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch g.genStep {
	case gpgGenStepUID:
		return g.updateGenerateUID(msg)

	case gpgGenStepAlgo:
		return g.updateGenerateAlgo(msg)

	case gpgGenStepExpiry:
		return g.updateGenerateExpiry(msg)
	}

	return g, nil
}

func (g gpgModel) updateGenerateUID(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		g.mode = gpgModeIdle
		g.input = ""
		g.status = ""
		return g, nil

	case "enter":
		val := strings.TrimSpace(g.input)
		if val == "" {
			g.status = "UID cannot be empty"
			return g, nil
		}

		if lt := strings.Index(val, "<"); lt < 0 || !strings.Contains(val[lt:], ">") {
			g.status = "UID must include <email>"
			return g, nil
		}

		g.genUID = val
		g.input = ""
		g.status = ""
		g.genStep = gpgGenStepAlgo
		return g, nil

	case "backspace":
		if len(g.input) > 0 {
			r := []rune(g.input)
			g.input = string(r[:len(r)-1])
		}

		return g, nil
	}

	if msg.Text != "" {
		g.input += msg.Text
	}

	return g, nil
}

func (g gpgModel) updateGenerateAlgo(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		g.mode = gpgModeIdle
		g.status = ""
		return g, nil

	case "enter":
		g.genStep = gpgGenStepExpiry
		g.input = "2y"
		g.status = ""
		return g, nil

	case "left", "h":
		if g.genAlgo > 0 {
			g.genAlgo--
		}

	case "right", "l":
		if g.genAlgo < len(gpgGenAlgoOptions)-1 {
			g.genAlgo++
		}
	}

	return g, nil
}

func (g gpgModel) updateGenerateExpiry(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		g.mode = gpgModeIdle
		g.input = ""
		g.status = ""
		return g, nil

	case "enter":
		val := strings.TrimSpace(g.input)
		if val == "" {
			val = "2y"
		}

		if strings.EqualFold(val, "never") {
			val = "0"
		}

		uid := g.genUID
		algo := gpgGenAlgoOptions[g.genAlgo]
		g.mode = gpgModeIdle
		g.input = ""
		return g, generateGPGKeyCmd(uid, algo, val)

	case "backspace":
		if len(g.input) > 0 {
			r := []rune(g.input)
			g.input = string(r[:len(r)-1])
		}

		return g, nil
	}

	if msg.Text != "" {
		g.input += msg.Text
	}

	return g, nil
}

func (g gpgModel) updateExpire(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		g.mode = gpgModeIdle
		g.input = ""

		return g, nil

	case "enter":
		k, sk, ok := g.currentSubKey()
		if !ok {
			g.mode = gpgModeIdle
			g.input = ""
			return g, nil
		}

		when := strings.TrimSpace(g.input)
		g.mode = gpgModeIdle
		g.input = ""

		if when == "" {
			return g, nil
		}

		subFpr := ""
		if !g.onPrimary() {
			subFpr = sk.Fingerprint
		}

		return g, expireCmd(k.Primary.Fingerprint, when, subFpr)

	case "backspace":
		if len(g.input) > 0 {
			r := []rune(g.input)
			g.input = string(r[:len(r)-1])
		}

		return g, nil
	}

	if msg.Text != "" {
		g.input += msg.Text
	}

	return g, nil
}

func (g gpgModel) view() string {
	if g.mode == gpgModeDetails {
		return g.renderDetails()
	}

	var s strings.Builder
	s.WriteString(g.renderList())

	switch g.mode {
	case gpgModeExpire:
		_, sk, ok := g.currentSubKey()
		if ok {
			s.WriteString("\n")
			fmt.Fprintf(&s, "Expire [%s]: %s_\n", sk.KeyID, g.input)
			s.WriteString(faintStyle.Render("1y, 2y, never, or YYYY-MM-DD — enter to confirm, esc to cancel"))
		}

	case gpgModeGenerate:
		s.WriteString("\n" + g.renderGenerate())

	case gpgModeDeleteConfirm:
		s.WriteString("\n" + g.renderDeleteConfirm())

	default:
		if g.status != "" {
			s.WriteString("\n" + faintStyle.Render(g.status))
		}
	}

	return s.String()
}

func (g gpgModel) renderGenerate() string {
	var sb strings.Builder

	switch g.genStep {
	case gpgGenStepUID:
		fmt.Fprintf(&sb, "UID: %s_\n", g.input)
		sb.WriteString(faintStyle.Render(`e.g. "Real Name <email@example.com>" — enter to confirm, esc to cancel`))

	case gpgGenStepAlgo:
		sb.WriteString("Algorithm: ")
		for i, opt := range gpgGenAlgoOptions {
			if i > 0 {
				sb.WriteString("  ")
			}

			if i == g.genAlgo {
				sb.WriteString(currentKeyStyle.Render("[" + opt + "]"))
			} else {
				sb.WriteString(faintStyle.Render(" " + opt + " "))
			}
		}

		sb.WriteString("\n" + faintStyle.Render("←/→ or h/l to choose — enter to confirm, esc to cancel"))

	case gpgGenStepExpiry:
		fmt.Fprintf(&sb, "Expiry: %s_\n", g.input)
		sb.WriteString(faintStyle.Render("1y, 2y, never, or YYYY-MM-DD — enter to confirm, esc to cancel"))
	}

	if g.status != "" {
		sb.WriteString("\n" + faintStyle.Render(g.status))
	}

	return sb.String()
}

func (g gpgModel) renderDetails() string {
	k, sk, ok := g.currentSubKey()
	if !ok {
		return ""
	}

	rows := [][2]string{
		{"UID", formatUIDPlain(k)},
		{"Validity", dashIfEmpty(k.Validity)},
	}

	if !g.onPrimary() {
		rows = append(rows, [2]string{"Primary", k.Primary.KeyID})
	}

	rows = append(rows,
		[2]string{"Fingerprint", formatFingerprint(sk.Fingerprint)},
		[2]string{"Key ID", sk.KeyID},
		[2]string{"Algorithm", sk.Algo},
		[2]string{"Capabilities", expandCaps(sk.Caps)},
		[2]string{"Created", formatDate(sk.Created)},
		[2]string{"Expires", formatExpiresDetail(sk.Expires, sk.Expired)},
		[2]string{"Secret", secretLocation(sk)},
	)

	if sk.CardSerial != "" {
		rows = append(rows, [2]string{"Card serial", sk.CardSerial})
	}

	var flags []string
	if sk.Revoked {
		flags = append(flags, "revoked")
	}

	if sk.Invalid {
		flags = append(flags, "invalid")
	}

	if sk.Disabled {
		flags = append(flags, "disabled")
	}

	if len(flags) > 0 {
		rows = append(rows, [2]string{"Status", strings.Join(flags, ", ")})
	}

	var sb strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&sb, "%-14s %s\n", r[0]+":", r[1])
	}

	sb.WriteString("\n" + faintStyle.Render("esc/enter - back"))
	return sb.String()
}

func formatUIDPlain(k Key) string {
	uid := k.PrimaryUID.Name

	if k.PrimaryUID.Comment != "" {
		uid = fmt.Sprintf("%s (%s)", uid, k.PrimaryUID.Comment)
	}

	if k.PrimaryUID.Email != "" {
		uid = fmt.Sprintf("%s <%s>", uid, k.PrimaryUID.Email)
	}

	return dashIfEmpty(uid)
}

func formatFingerprint(fpr string) string {
	if len(fpr) != 40 {
		return fpr
	}

	var sb strings.Builder
	for i := 0; i < 40; i += 4 {
		if i > 0 {
			sb.WriteByte(' ')
			if i == 20 {
				sb.WriteByte(' ')
			}
		}

		sb.WriteString(fpr[i : i+4])
	}

	return sb.String()
}

func expandCaps(caps string) string {
	if caps == "" {
		return "-"
	}

	names := map[byte]string{
		'S': "sign",
		'C': "certify",
		'E': "encrypt",
		'A': "authenticate",
	}

	var parts []string
	for i := 0; i < len(caps); i++ {
		if name, ok := names[caps[i]]; ok {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return caps
	}

	return strings.Join(parts, ", ")
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	return t.Format("2006-01-02")
}

func formatExpiresDetail(t time.Time, expired bool) string {
	if t.IsZero() {
		return "never"
	}

	date := t.Format("2006-01-02")
	if expired {
		return fmt.Sprintf("%s (expired)", date)
	}

	return fmt.Sprintf("%s (%s)", date, relativeExpires(t, time.Now()))
}

func secretLocation(sk SubKey) string {
	if !sk.Secret {
		return "not available"
	}

	if sk.CardSerial != "" {
		return "on card"
	}

	return "on disk"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}

	return s
}

func (g gpgModel) renderList() string {
	var s strings.Builder

	if g.err != nil {
		fmt.Fprintf(&s, "Error loading GPG keys: %v\n", g.err)
		return s.String()
	}

	if len(g.keys) == 0 {
		s.WriteString("No GPG keys found.\n")
		return s.String()
	}

	itemIdx := 0

	for i, k := range g.keys {
		s.WriteString("  " + faintStyle.Render("uid   "+formatUIDRow(k)) + "\n")
		s.WriteString(renderNavRow("pub", k.Primary, itemIdx == g.cursor) + "\n")
		itemIdx++

		for _, sub := range k.SubKeys {
			s.WriteString(renderNavRow("sub", sub, itemIdx == g.cursor) + "\n")
			itemIdx++
		}

		if i < len(g.keys)-1 {
			s.WriteString("\n")
		}
	}

	return s.String()
}

func renderNavRow(label string, sk SubKey, selected bool) string {
	marker := "  "
	style := faintStyle

	if selected {
		marker = cursorStyle.Render("> ")
		style = currentKeyStyle
	}

	return marker + style.Render(label+"   "+sk.KeyID+"  "+formatKeyRow(sk, selected))
}

func formatUIDRow(k Key) string {
	uid := k.PrimaryUID.Name

	if k.PrimaryUID.Comment != "" {
		uid = fmt.Sprintf("%s (%s)", uid, k.PrimaryUID.Comment)
	}

	if k.PrimaryUID.Email != "" {
		uid = fmt.Sprintf("%s <%s>", uid, k.PrimaryUID.Email)
	}

	if k.Validity != "" {
		return fmt.Sprintf("[%s] %s", k.Validity, uid)
	}

	return uid
}

func formatKeyRow(sk SubKey, selected bool) string {
	parts := []string{sk.Algo}

	if sk.CardSerial != "" {
		parts = append(parts, "[card]")
	} else if sk.Secret {
		parts = append(parts, "[disk]")
	}

	if sk.Caps != "" {
		parts = append(parts, fmt.Sprintf("[%s]", sk.Caps))
	}

	parts = append(parts, expiryLabel(sk.Expires, sk.Expired, selected))

	if sk.Revoked {
		parts = append(parts, "[revoked]")
	}

	if sk.Invalid {
		parts = append(parts, "[invalid]")
	}

	if sk.Disabled {
		parts = append(parts, "[disabled]")
	}

	return strings.Join(parts, "  ")
}

func expiryLabel(t time.Time, expired, selected bool) string {
	if t.IsZero() {
		return "[no expiry]"
	}

	if expired {
		return "[expired]"
	}

	now := time.Now()
	label := "[" + relativeExpires(t, now) + "]"

	if expiringSoon(t, now) {
		if selected {
			return warningStyle.Render(label)
		}

		return warningFaintStyle.Render(label)
	}

	return label
}

func (g gpgModel) renderDeleteConfirm() string {
	k, _, ok := g.currentSubKey()
	if !ok {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Delete this key?\n")
	fmt.Fprintf(&sb, "  UID:         %s\n", formatUIDPlain(k))
	fmt.Fprintf(&sb, "  Key ID:      %s\n", k.Primary.KeyID)
	fmt.Fprintf(&sb, "  Fingerprint: %s\n", formatFingerprint(k.Primary.Fingerprint))

	var parts []string
	if k.Primary.Secret {
		if k.Primary.CardSerial != "" {
			parts = append(parts, "secret stub (card untouched)")
		} else {
			parts = append(parts, "secret key")
		}
	}

	parts = append(parts, "public key")
	fmt.Fprintf(&sb, "  Removes:     %s — local keyring only, no recovery without backup\n", strings.Join(parts, " + "))

	sb.WriteString(faintStyle.Render("y to confirm, anything else to cancel"))
	return sb.String()
}

func yankGPGCmd(fpr, keyID string) tea.Cmd {
	return func() tea.Msg {
		out, err := runGPG("--armor", "--export", fpr)
		if err != nil {
			return gpgYankDoneMsg{keyID: keyID, err: err}
		}

		tool, args := clipboardTool()
		if tool == "" {
			return gpgYankDoneMsg{keyID: keyID, err: fmt.Errorf("no clipboard tool found (install wl-clipboard, xclip, or xsel)")}
		}

		c := exec.Command(tool, args...)
		c.Stdin = strings.NewReader(string(out))
		return gpgYankDoneMsg{keyID: keyID, err: c.Run()}
	}
}

func deleteGPGKeyCmd(fpr, keyID string, hasSecret bool) tea.Cmd {
	return func() tea.Msg {
		if hasSecret {
			if _, err := runGPG("--batch", "--yes", "--delete-secret-keys", fpr); err != nil {
				return gpgDeleteDoneMsg{keyID: keyID, err: err}
			}
		}

		if _, err := runGPG("--batch", "--yes", "--delete-keys", fpr); err != nil {
			return gpgDeleteDoneMsg{keyID: keyID, err: err}
		}

		return gpgDeleteDoneMsg{keyID: keyID}
	}
}

func generateGPGKeyCmd(uid, algo, expiry string) tea.Cmd {
	c := exec.Command("gpg", "--quick-generate-key", uid, algo, "default", expiry)

	return tea.ExecProcess(c, func(err error) tea.Msg {
		return gpgGenerateDoneMsg{err: err}
	})
}

func passphraseCmd(primaryFpr string) tea.Cmd {
	c := exec.Command("gpg", "--passwd", primaryFpr)

	return tea.ExecProcess(c, func(err error) tea.Msg {
		return gpgPassphraseDoneMsg{err: err}
	})
}

func expireCmd(primaryFpr, when, subFpr string) tea.Cmd {
	if strings.EqualFold(when, "never") {
		when = "0"
	}

	args := []string{"--quick-set-expire", primaryFpr, when}
	if subFpr != "" {
		args = append(args, subFpr)
	}

	c := exec.Command("gpg", args...)

	return tea.ExecProcess(c, func(err error) tea.Msg {
		return gpgExpireDoneMsg{err: err}
	})
}

func reloadGPGKeysCmd() tea.Msg {
	keys, err := LoadKeys()
	return gpgKeysReloadedMsg{keys: keys, err: err}
}
