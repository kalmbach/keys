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
)

type gpgExpireDoneMsg struct{ err error }

type gpgKeysReloadedMsg struct {
	keys []Key
	err  error
}

type gpgNavItem struct {
	keyIdx int
	subIdx int // -1 for primary
}

type gpgModel struct {
	keys   []Key
	cursor int
	mode   gpgMode
	input  string
	status string
	err    error
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
		if g.mode == gpgModeExpire {
			return g.updateExpire(msg)
		}

		return g.updateIdle(msg)

	case gpgExpireDoneMsg:
		if msg.err != nil {
			g.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			g.status = "expiry updated"
		}

		return g, reloadGPGKeysCmd

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
	var s strings.Builder
	s.WriteString(g.renderList())

	if g.mode == gpgModeExpire {
		_, sk, ok := g.currentSubKey()
		if ok {
			s.WriteString("\n")
			fmt.Fprintf(&s, "Expire [%s]: %s_\n", sk.KeyID, g.input)
			s.WriteString(faintStyle.Render("1y, 2y, never, or YYYY-MM-DD — enter to confirm, esc to cancel"))
		}

	} else if g.status != "" {
		s.WriteString("\n" + faintStyle.Render(g.status))
	}

	return s.String()
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

	return marker + style.Render(label+"   "+sk.KeyID+"  "+formatKeyRow(sk))
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

func formatKeyRow(sk SubKey) string {
	parts := []string{sk.Algo}

	if !sk.Created.IsZero() {
		parts = append(parts, sk.Created.Format(time.DateOnly))
	}

	if sk.Caps != "" {
		parts = append(parts, fmt.Sprintf("[%s]", sk.Caps))
	}

	parts = append(parts, expiryLabel(sk.Expires, sk.Expired))

	if sk.Revoked {
		parts = append(parts, "[revoked]")
	}

	return strings.Join(parts, "  ")
}

func expiryLabel(t time.Time, expired bool) string {
	if t.IsZero() {
		return "[no expiry]"
	}

	if expired {
		return fmt.Sprintf("[expired %s]", t.Format(time.DateOnly))
	}

	return fmt.Sprintf("[expires %s]", t.Format(time.DateOnly))
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
