package main

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Catppuccin Mocha subset — https://catppuccin.com/palette
var (
	mochaText      = lipgloss.Color("#cdd6f4")
	mochaOverlay0  = lipgloss.Color("#6c7086")
	mochaMauve     = lipgloss.Color("#cba6f7")
	mochaMaroon    = lipgloss.Color("#eba0ac")
	mochaMaroonDim = lipgloss.Color("#8d6068")

	logoStyle         = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	titleStyle        = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	cursorStyle       = lipgloss.NewStyle().Foreground(mochaMauve).Bold(true)
	currentKeyStyle   = lipgloss.NewStyle().Foreground(mochaText)
	faintStyle        = lipgloss.NewStyle().Foreground(mochaOverlay0)
	expiredStyle      = lipgloss.NewStyle().Foreground(mochaMaroon)
	expiredFaintStyle = lipgloss.NewStyle().Foreground(mochaMaroonDim)
)

const logoArt = "▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝"

func renderHeader(title string) string {
	logo := "\n" + logoStyle.Render(logoArt)
	info := "\n" + titleStyle.Render(title) + "\n" + faintStyle.Render("v"+version)
	return lipgloss.JoinHorizontal(lipgloss.Top, logo, "  ", info)
}

type source int

const (
	sourceGPG source = iota
	sourceSSH
)

type model struct {
	source   source
	showHelp bool
	gpg      gpgModel
	ssh      sshModel
}

func newModel() model {
	gpgKeys, gpgErr := LoadKeys()
	sshKeys, sshErr := LoadSSHKeys()
	return model{
		gpg: gpgModel{keys: gpgKeys, err: gpgErr},
		ssh: sshModel{keys: sshKeys, err: sshErr},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		return m.handleKey(key)
	}

	var cmd tea.Cmd
	switch msg.(type) {
	case gpgExpireDoneMsg, gpgKeysReloadedMsg:
		m.gpg, cmd = m.gpg.update(msg)
	case sshGenerateDoneMsg, sshChangeCommentDoneMsg, sshChangePassphraseDoneMsg, sshDeleteDoneMsg, sshDetailsMsg, sshKeysReloadedMsg, sshClipboardDoneMsg:
		m.ssh, cmd = m.ssh.update(msg)
	}
	return m, cmd
}

func (m model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.showHelp {
		if s := msg.String(); s == "esc" || s == "?" {
			m.showHelp = false
		}
		return m, nil
	}

	if m.gpg.idle() && m.ssh.idle() {
		switch msg.String() {
		case "esc", "q":
			return m, tea.Quit

		case "tab":
			if m.source == sourceGPG {
				m.source = sourceSSH
				m.ssh.cursor = 0
				m.ssh.status = ""

			} else {
				m.source = sourceGPG
				m.gpg.cursor = 0
				m.gpg.status = ""
			}
			return m, nil

		case "?":
			m.showHelp = true
			return m, nil
		}
	}

	var cmd tea.Cmd
	switch m.source {
	case sourceGPG:
		m.gpg, cmd = m.gpg.update(msg)
	case sourceSSH:
		m.ssh, cmd = m.ssh.update(msg)
	}

	return m, cmd
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
		s.WriteString("? - hide help\n")

		switch m.source {
		case sourceGPG:
			s.WriteString("\n" + faintStyle.Render("GPG keys") + "\n")
			s.WriteString("e - edit expiry. " + faintStyle.Render("Runs gpg --quick-set-expire {fingerprint} {when}") + "\n")

		case sourceSSH:
			s.WriteString("\n" + faintStyle.Render("SSH keys") + "\n")
			s.WriteString("enter - show details\n")
			s.WriteString("y - yank public key\n")
			s.WriteString("g - generate new key. " + faintStyle.Render("Runs ssh-keygen -t {keyType} -C {comment} -f {path}") + "\n")
			s.WriteString("c - change comment. " + faintStyle.Render("Runs ssh-keygen -c -C {comment} -f {path}") + "\n")
			s.WriteString("p - change passphrase. " + faintStyle.Render("Runs ssh-keygen -p -f {path}") + "\n")
			s.WriteString("d - delete key pair\n")
		}

		s.WriteString("\n" + faintStyle.Render("esc - go back"))
		return tea.NewView(s.String())
	}

	var body string
	var idle bool
	switch m.source {
	case sourceGPG:
		body = m.gpg.view()
		idle = m.gpg.idle()
	case sourceSSH:
		body = m.ssh.view()
		idle = m.ssh.idle()
	}
	s.WriteString(body)

	if idle {
		s.WriteString(faintStyle.Render("\n? - help, q/esc - quit"))
	}

	return tea.NewView(s.String())
}
