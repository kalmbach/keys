package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Catppuccin Mocha subset — https://catppuccin.com/palette
var (
	mochaBase     = lipgloss.Color("#1e1e2e")
	mochaText     = lipgloss.Color("#cdd6f4")
	mochaOverlay0 = lipgloss.Color("#6c7086")
	mochaMauve    = lipgloss.Color("#cba6f7")

	appNameStyle    = lipgloss.NewStyle().Background(mochaMauve).Foreground(mochaBase).Bold(true).Padding(0, 1)
	cursorStyle     = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	currentKeyStyle = lipgloss.NewStyle().Foreground(mochaText)
	faintStyle      = lipgloss.NewStyle().Foreground(mochaOverlay0)
)

const (
	appName string = "KEYS"
)

type mode int

const (
	modeIdle mode = iota
	modeExpire
)

type expireDoneMsg struct{ err error }

type keysReloadedMsg struct {
	keys []Key
	err  error
}

type model struct {
	keys     []Key
	cursor   int
	mode     mode
	input    string
	status   string
	err      error
	showHelp bool
}

func newModel() model {
	keys, err := LoadKeys()
	return model{keys: keys, err: err}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		if m.mode == modeExpire {
			return m.updateExpire(msg)
		}
		return m.updateIdle(msg)
	case expireDoneMsg:
		if msg.err != nil {
			m.status = fmt.Sprintf("gpg error: %v", msg.err)
		} else {
			m.status = "expiry updated"
		}
		return m, reloadKeysCmd
	case keysReloadedMsg:
		m.keys = msg.keys
		m.err = msg.err
		if m.cursor >= len(m.keys) {
			m.cursor = len(m.keys) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		return m, nil
	}
	return m, nil
}

func (m model) updateIdle(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.showHelp {
		switch msg.String() {
		case "esc", "?":
			m.showHelp = false
		}
		return m, nil
	}
	switch msg.String() {
	case "esc", "q":
		return m, tea.Quit
	case "up", "k":
		if m.err == nil && m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.err == nil && m.cursor < len(m.keys)-1 {
			m.cursor++
		}
	case "e":
		if m.err == nil && len(m.keys) > 0 {
			if !m.keys[m.cursor].Secret {
				m.status = "can't edit expiry: no secret key"
			} else {
				m.mode = modeExpire
				m.input = ""
				m.status = ""
			}
		}
	case "?":
		m.showHelp = true
	}
	return m, nil
}

func (m model) updateExpire(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeIdle
		m.input = ""
		return m, nil
	case "enter":
		fp := m.keys[m.cursor].Fingerprint
		when := strings.TrimSpace(m.input)
		m.mode = modeIdle
		m.input = ""
		if when == "" {
			return m, nil
		}
		return m, expireCmd(fp, when)
	case "backspace":
		if len(m.input) > 0 {
			r := []rune(m.input)
			m.input = string(r[:len(r)-1])
		}
		return m, nil
	}
	if msg.Text != "" {
		m.input += msg.Text
	}
	return m, nil
}

func expireCmd(fingerprint, when string) tea.Cmd {
	if strings.EqualFold(when, "never") {
		when = "0"
	}
	c := exec.Command("gpg", "--quick-set-expire", fingerprint, when)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return expireDoneMsg{err: err}
	})
}

func reloadKeysCmd() tea.Msg {
	keys, err := LoadKeys()
	return keysReloadedMsg{keys: keys, err: err}
}

func (m model) View() tea.View {
	var s strings.Builder
	title := appName
	if m.showHelp {
		title = "HELP"
	}

	s.WriteString(appNameStyle.Render(title) + "\n\n")

	if m.showHelp {
		s.WriteString("↑/↓ or j/k - move\n")
		s.WriteString("e - edit expiry\n")
		s.WriteString("? - hide help\n")
		s.WriteString("\n" + faintStyle.Render("esc - go back"))
		return tea.NewView(s.String())
	}

	if m.err != nil {
		fmt.Fprintf(&s, "Error loading keys: %v\n", m.err)
		s.WriteString("\nq - quit")
		return tea.NewView(s.String())
	}

	if len(m.keys) == 0 {
		s.WriteString("No keys found.\n")
	} else {
		for i, k := range m.keys {
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
			if i == m.cursor {
				marker = cursorStyle.Render("> ")
				style = currentKeyStyle
			}
			line := fmt.Sprintf("[%s]  %s  %s  [%s]", kind, k.KeyID, uid, expiry)
			s.WriteString(marker + style.Render(line) + "\n")
		}
	}

	if m.mode == modeExpire && len(m.keys) > 0 {
		keyID := m.keys[m.cursor].KeyID
		s.WriteString("\n")
		fmt.Fprintf(&s, "Expire [%s]: %s_\n", keyID, m.input)
		s.WriteString(faintStyle.Render("1y, 2y, never, or YYYY-MM-DD — enter to confirm, esc to cancel"))
	} else {
		if m.status != "" {
			s.WriteString("\n" + faintStyle.Render(m.status))
		}
		s.WriteString(faintStyle.Render("\n? - help, q/esc - quit"))
	}
	return tea.NewView(s.String())
}
