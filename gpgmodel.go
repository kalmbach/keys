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

		if g.cursor >= len(g.keys) {
			g.cursor = len(g.keys) - 1
		}

		if g.cursor < 0 {
			g.cursor = 0
		}

		return g, nil
	}
	return g, nil
}

func (g gpgModel) updateIdle(msg tea.KeyPressMsg) (gpgModel, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if g.err == nil && g.cursor > 0 {
			g.cursor--
		}

	case "down", "j":
		if g.err == nil && g.cursor < len(g.keys)-1 {
			g.cursor++
		}

	case "e":
		if g.err == nil && len(g.keys) > 0 {
			if !g.keys[g.cursor].Secret {
				g.status = "can't edit expiry: no secret key"

			} else {
				g.mode = gpgModeExpire
				g.input = ""
				g.status = ""
			}
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
		fp := g.keys[g.cursor].Fingerprint
		when := strings.TrimSpace(g.input)
		g.mode = gpgModeIdle
		g.input = ""

		if when == "" {
			return g, nil
		}

		return g, expireCmd(fp, when)

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

	if g.mode == gpgModeExpire && len(g.keys) > 0 {
		keyID := g.keys[g.cursor].KeyID
		s.WriteString("\n")
		fmt.Fprintf(&s, "Expire [%s]: %s_\n", keyID, g.input)
		s.WriteString(faintStyle.Render("1y, 2y, never, or YYYY-MM-DD — enter to confirm, esc to cancel"))

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

	for i, k := range g.keys {
		kind := "pub"
		if k.Secret {
			kind = "sec"
		}

		expiry := "no expiry"
		if !k.Expires.IsZero() {
			if k.Expired {
				expiry = fmt.Sprintf("expired %s", k.Expires.Format(time.DateOnly))
			} else {
				expiry = fmt.Sprintf("expires %s", k.Expires.Format(time.DateOnly))
			}
		}

		uid := k.PrimaryUID.Name
		if k.PrimaryUID.Comment != "" {
			uid = fmt.Sprintf("%s (%s)", uid, k.PrimaryUID.Comment)
		}

		if k.PrimaryUID.Email != "" {
			uid = fmt.Sprintf("%s <%s>", uid, k.PrimaryUID.Email)
		}

		marker := "  "
		style := faintStyle

		if i == g.cursor {
			marker = cursorStyle.Render("> ")
			style = currentKeyStyle
		}

		line := fmt.Sprintf("[%s]  %s  %s  [%s]", kind, k.KeyID, uid, expiry)
		s.WriteString(marker + style.Render(line) + "\n")
	}

	return s.String()
}

func expireCmd(fingerprint, when string) tea.Cmd {
	if strings.EqualFold(when, "never") {
		when = "0"
	}

	c := exec.Command("gpg", "--quick-set-expire", fingerprint, when)

	return tea.ExecProcess(c, func(err error) tea.Msg {
		return gpgExpireDoneMsg{err: err}
	})
}

func reloadGPGKeysCmd() tea.Msg {
	keys, err := LoadKeys()
	return gpgKeysReloadedMsg{keys: keys, err: err}
}
