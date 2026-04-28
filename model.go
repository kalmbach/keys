package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Catppuccin Mocha subset — https://catppuccin.com/palette
var (
	mochaText     = lipgloss.Color("#cdd6f4")
	mochaOverlay0 = lipgloss.Color("#6c7086")
	mochaMauve    = lipgloss.Color("#cba6f7")

	logoStyle       = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	titleStyle      = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	cursorStyle     = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	currentKeyStyle = lipgloss.NewStyle().Foreground(mochaText)
	faintStyle      = lipgloss.NewStyle().Foreground(mochaOverlay0)
)

const logoArt = "▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝"

func renderHeader(title string) string {
	logo := "\n" + logoStyle.Render(logoArt)
	info := "\n" + titleStyle.Render(title) + "\n" + faintStyle.Render("v"+version)
	return lipgloss.JoinHorizontal(lipgloss.Top, logo, "  ", info)
}

type mode int

const (
	modeIdle mode = iota
	modeExpire
)

type source int

const (
	sourceGPG source = iota
	sourceSSH
)

type expireDoneMsg struct{ err error }

type clipboardDoneMsg struct {
	filename string
	err      error
}

type gpgKeysReloadedMsg struct {
	keys []Key
	err  error
}

type model struct {
	gpgKeys  []Key
	sshKeys  []SSHKey
	cursor   int
	mode     mode
	source   source
	input    string
	status   string
	gpgErr   error
	sshErr   error
	showHelp bool
}

func newModel() model {
	gpgKeys, gpgErr := LoadKeys()
	sshKeys, sshErr := LoadSSHKeys()
	return model{gpgKeys: gpgKeys, gpgErr: gpgErr, sshKeys: sshKeys, sshErr: sshErr}
}

func (m model) currentErr() error {
	if m.source == sourceSSH {
		return m.sshErr
	}
	return m.gpgErr
}

func (m model) currentLen() int {
	if m.source == sourceSSH {
		return len(m.sshKeys)
	}
	return len(m.gpgKeys)
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
	case clipboardDoneMsg:
		if msg.err != nil {
			m.status = fmt.Sprintf("clipboard error: %v", msg.err)
		} else {
			m.status = fmt.Sprintf("copied %s", msg.filename)
		}
		return m, nil
	case gpgKeysReloadedMsg:
		m.gpgKeys = msg.keys
		m.gpgErr = msg.err
		if m.cursor >= len(m.gpgKeys) {
			m.cursor = len(m.gpgKeys) - 1
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
	case "tab":
		if m.source == sourceGPG {
			m.source = sourceSSH
		} else {
			m.source = sourceGPG
		}
		m.cursor = 0
		m.status = ""
	case "up", "k":
		if m.currentErr() == nil && m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.currentErr() == nil && m.cursor < m.currentLen()-1 {
			m.cursor++
		}
	case "e":
		if m.source == sourceGPG && m.gpgErr == nil && len(m.gpgKeys) > 0 {
			if !m.gpgKeys[m.cursor].Secret {
				m.status = "can't edit expiry: no secret key"
			} else {
				m.mode = modeExpire
				m.input = ""
				m.status = ""
			}
		}
	case "y":
		if m.source == sourceSSH && m.sshErr == nil && len(m.sshKeys) > 0 {
			k := m.sshKeys[m.cursor]
			return m, yankCmd(k.Path, k.Filename)
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
		fp := m.gpgKeys[m.cursor].Fingerprint
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
	return gpgKeysReloadedMsg{keys: keys, err: err}
}

func yankCmd(path, filename string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return clipboardDoneMsg{filename: filename, err: err}
		}

		tool, args := clipboardTool()
		if tool == "" {
			return clipboardDoneMsg{filename: filename, err: errors.New("no clipboard tool found (install wl-clipboard, xclip, or xsel)")}
		}

		c := exec.Command(tool, args...)
		c.Stdin = strings.NewReader(string(data))

		return clipboardDoneMsg{filename: filename, err: c.Run()}
	}
}

func clipboardTool() (string, []string) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if _, err := exec.LookPath("wl-copy"); err == nil {
			return "wl-copy", nil
		}
	}

	if _, err := exec.LookPath("xclip"); err == nil {
		return "xclip", []string{"-selection", "clipboard"}
	}

	if _, err := exec.LookPath("xsel"); err == nil {
		return "xsel", []string{"--clipboard", "--input"}
	}

	return "", nil
}

func (m model) View() tea.View {
	var s strings.Builder
	title := "GPG KEYS"

	if m.source == sourceSSH {
		title = "SSH KEYS"
	}

	if m.showHelp {
		title = "HELP"
	}

	s.WriteString(renderHeader(title) + "\n\n")

	if m.showHelp {
		s.WriteString("tab - switch GPG/SSH\n")
		s.WriteString("↑/↓ or j/k - move\n")
		s.WriteString("e - edit expiry (GPG only)\n")
		s.WriteString("y - yank public key (SSH only)\n")
		s.WriteString("? - hide help\n")
		s.WriteString("\n" + faintStyle.Render("esc - go back"))
		return tea.NewView(s.String())
	}

	switch m.source {
	case sourceGPG:
		s.WriteString(renderGPGList(m))
	case sourceSSH:
		s.WriteString(renderSSHList(m))
	}

	if m.source == sourceGPG && m.mode == modeExpire && len(m.gpgKeys) > 0 {
		keyID := m.gpgKeys[m.cursor].KeyID
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

func renderGPGList(m model) string {
	var s strings.Builder

	if m.gpgErr != nil {
		fmt.Fprintf(&s, "Error loading GPG keys: %v\n", m.gpgErr)
		return s.String()
	}

	if len(m.gpgKeys) == 0 {
		s.WriteString("No GPG keys found.\n")
		return s.String()
	}

	for i, k := range m.gpgKeys {
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

	return s.String()
}

func renderSSHList(m model) string {
	var s strings.Builder

	if m.sshErr != nil {
		fmt.Fprintf(&s, "Error loading SSH keys: %v\n", m.sshErr)
		return s.String()
	}

	if len(m.sshKeys) == 0 {
		s.WriteString("No SSH keys found.\n")
		return s.String()
	}

	for i, k := range m.sshKeys {
		kind := "pub"
		if k.HasPrivate {
			kind = "sec"
		}

		marker := "  "
		style := faintStyle
		if i == m.cursor {
			marker = cursorStyle.Render("> ")
			style = currentKeyStyle
		}
		comment := k.Comment
		if comment == "" {
			comment = "-"
		}
		line := fmt.Sprintf("[%s]  %s  %s  (%s)", kind, k.Type, comment, k.Filename)
		s.WriteString(marker + style.Render(line) + "\n")
	}

	return s.String()
}
