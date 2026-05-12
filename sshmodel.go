package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
)

type sshMode int

const (
	sshModeIdle sshMode = iota
	sshModeGenerate
	sshModeDeleteConfirm
	sshModeDetails
)

type genStep int

const (
	genStepType genStep = iota
	genStepComment
	genStepFilename
)

type sshGenerateDoneMsg struct{ err error }

type sshDeleteDoneMsg struct {
	name string
	err  error
}

type sshDetailsMsg struct {
	details sshDetails
}

type sshDetails struct {
	bits        string
	randomart   string
	agentStatus string
}

type sshClipboardDoneMsg struct {
	filename string
	err      error
}

type sshKeysReloadedMsg struct {
	keys []SSHKey
	err  error
}

type sshModel struct {
	keys       []SSHKey
	cursor     int
	mode       sshMode
	input      string
	status     string
	err        error
	genStep    genStep
	genType    string
	genComment string
	details    sshDetails
}

func (s sshModel) idle() bool {
	return s.mode == sshModeIdle
}

func (s sshModel) update(msg tea.Msg) (sshModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch s.mode {
		case sshModeGenerate:
			return s.updateGenerate(msg)
		case sshModeDeleteConfirm:
			return s.updateDeleteConfirm(msg)
		case sshModeDetails:
			return s.updateDetails(msg)
		}
		return s.updateIdle(msg)
	case sshGenerateDoneMsg:
		if msg.err != nil {
			s.status = fmt.Sprintf("ssh-keygen error: %v", msg.err)
		} else {
			s.status = "key generated"
		}
		return s, reloadSSHKeysCmd
	case sshDeleteDoneMsg:
		if msg.err != nil {
			s.status = fmt.Sprintf("delete error: %v", msg.err)
		} else {
			s.status = fmt.Sprintf("deleted %s", msg.name)
		}
		return s, reloadSSHKeysCmd
	case sshClipboardDoneMsg:
		if msg.err != nil {
			s.status = fmt.Sprintf("clipboard error: %v", msg.err)
		} else {
			s.status = fmt.Sprintf("copied %s", msg.filename)
		}
		return s, nil
	case sshDetailsMsg:
		s.details = msg.details
		return s, nil
	case sshKeysReloadedMsg:
		s.keys = msg.keys
		s.err = msg.err
		if s.cursor >= len(s.keys) {
			s.cursor = len(s.keys) - 1
		}
		if s.cursor < 0 {
			s.cursor = 0
		}
		return s, nil
	}
	return s, nil
}

func (s sshModel) updateIdle(msg tea.KeyPressMsg) (sshModel, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if s.err == nil && s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.err == nil && s.cursor < len(s.keys)-1 {
			s.cursor++
		}
	case "y":
		if s.err == nil && len(s.keys) > 0 {
			k := s.keys[s.cursor]
			return s, yankCmd(k.Path, k.Filename)
		}
	case "g":
		if s.err == nil {
			s.mode = sshModeGenerate
			s.genStep = genStepType
			s.genType = ""
			s.genComment = ""
			s.input = ""
			s.status = ""
		}
	case "d":
		if s.err == nil && len(s.keys) > 0 {
			s.mode = sshModeDeleteConfirm
			s.status = ""
		}
	case "enter":
		if s.err == nil && len(s.keys) > 0 {
			k := s.keys[s.cursor]
			s.mode = sshModeDetails
			s.details = sshDetails{}
			s.status = ""
			return s, fetchSSHDetailsCmd(k.Path, k.Fingerprint)
		}
	}
	return s, nil
}

func (s sshModel) updateDetails(msg tea.KeyPressMsg) (sshModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q":
		s.mode = sshModeIdle
		s.details = sshDetails{}
	}
	return s, nil
}

func (s sshModel) updateDeleteConfirm(msg tea.KeyPressMsg) (sshModel, tea.Cmd) {
	if len(s.keys) == 0 {
		s.mode = sshModeIdle
		return s, nil
	}
	if k := msg.String(); k == "y" || k == "Y" {
		key := s.keys[s.cursor]
		priv := strings.TrimSuffix(key.Path, ".pub")
		name := strings.TrimSuffix(key.Filename, ".pub")
		s.mode = sshModeIdle
		return s, deleteSSHKeyCmd(priv, key.Path, name)
	}
	s.mode = sshModeIdle
	return s, nil
}

func (s sshModel) updateGenerate(msg tea.KeyPressMsg) (sshModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.mode = sshModeIdle
		s.input = ""
		return s, nil
	case "enter":
		val := strings.TrimSpace(s.input)
		s.input = ""
		switch s.genStep {
		case genStepType:
			if val == "" {
				val = "ed25519"
			}
			s.genType = val
			s.genStep = genStepComment
			return s, nil
		case genStepComment:
			if val == "" {
				val = defaultSSHComment()
			}
			s.genComment = val
			s.genStep = genStepFilename
			return s, nil
		case genStepFilename:
			if val == "" {
				val = "id_" + s.genType
			}
			path, err := resolveSSHKeyPath(val)
			if err != nil {
				s.mode = sshModeIdle
				s.status = fmt.Sprintf("path error: %v", err)
				return s, nil
			}
			s.mode = sshModeIdle
			return s, generateKeyCmd(s.genType, s.genComment, path)
		}
	case "backspace":
		if len(s.input) > 0 {
			r := []rune(s.input)
			s.input = string(r[:len(r)-1])
		}
		return s, nil
	}

	if msg.Text != "" {
		s.input += msg.Text
	}

	return s, nil
}

func (s sshModel) view() string {
	if s.mode == sshModeDetails && len(s.keys) > 0 {
		return s.renderDetails()
	}

	var sb strings.Builder
	sb.WriteString(s.renderList())

	if s.mode == sshModeGenerate {
		label, hint := s.prompt()
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "%s: %s_\n", label, s.input)
		sb.WriteString(faintStyle.Render(hint))
	} else if s.mode == sshModeDeleteConfirm && len(s.keys) > 0 {
		k := s.keys[s.cursor]
		name := strings.TrimSuffix(k.Filename, ".pub")
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "Delete %s and %s? ", name, k.Filename)
		sb.WriteString(faintStyle.Render("y to confirm, anything else to cancel"))
	} else if s.status != "" {
		sb.WriteString("\n" + faintStyle.Render(s.status))
	}
	return sb.String()
}

func (s sshModel) prompt() (string, string) {
	switch s.genStep {
	case genStepType:
		return "Type", "ed25519 (default), rsa, ecdsa — enter to confirm, esc to cancel"
	case genStepComment:
		return "Comment", fmt.Sprintf("default: %s — enter to confirm, esc to cancel", defaultSSHComment())
	case genStepFilename:
		return "Filename", fmt.Sprintf("default: ~/.ssh/id_%s — relative paths go under ~/.ssh — enter to confirm, esc to cancel", s.genType)
	}
	return "", ""
}

func (s sshModel) renderDetails() string {
	k := s.keys[s.cursor]
	bits := s.details.bits
	if bits == "" {
		bits = "…"
	}
	agent := s.details.agentStatus
	if agent == "" {
		agent = "…"
	}
	comment := k.Comment
	if comment == "" {
		comment = "-"
	}
	priv := "no"
	if k.HasPrivate {
		priv = "yes"
	}

	rows := [][2]string{
		{"File", k.Path},
		{"Type", k.Type},
		{"Bits", bits},
		{"Fingerprint", k.Fingerprint},
		{"Comment", comment},
		{"Private key", priv},
		{"Agent", agent},
	}

	var sb strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&sb, "%-13s %s\n", r[0]+":", r[1])
	}
	if s.details.randomart != "" {
		sb.WriteString("\n" + s.details.randomart + "\n")
	}
	sb.WriteString("\n" + faintStyle.Render("esc/enter - back"))
	return sb.String()
}

func (s sshModel) renderList() string {
	var sb strings.Builder

	if s.err != nil {
		fmt.Fprintf(&sb, "Error loading SSH keys: %v\n", s.err)
		return sb.String()
	}

	if len(s.keys) == 0 {
		sb.WriteString("No SSH keys found.\n")
		return sb.String()
	}

	for i, k := range s.keys {
		kind := "pub"
		if k.HasPrivate {
			kind = "sec"
		}

		marker := "  "
		style := faintStyle
		if i == s.cursor {
			marker = cursorStyle.Render("> ")
			style = currentKeyStyle
		}
		comment := k.Comment
		if comment == "" {
			comment = "-"
		}
		line := fmt.Sprintf("[%s]  %s  %s  (%s)", kind, k.Type, comment, k.Filename)
		sb.WriteString(marker + style.Render(line) + "\n")
	}

	return sb.String()
}

func defaultSSHComment() string {
	user := os.Getenv("USER")
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	if user == "" {
		return host
	}
	return user + "@" + host
}

func resolveSSHKeyPath(in string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(in, "~/") {
		return filepath.Join(home, in[2:]), nil
	}
	if filepath.IsAbs(in) {
		return in, nil
	}
	return filepath.Join(home, ".ssh", in), nil
}

func generateKeyCmd(keyType, comment, path string) tea.Cmd {
	c := exec.Command("ssh-keygen", "-t", keyType, "-C", comment, "-f", path)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return sshGenerateDoneMsg{err: err}
	})
}

func fetchSSHDetailsCmd(path, fingerprint string) tea.Cmd {
	return func() tea.Msg {
		d := sshDetails{}

		if out, err := exec.Command("ssh-keygen", "-l", "-v", "-f", path).Output(); err == nil {
			lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
			if len(lines) > 0 {
				if fields := strings.Fields(lines[0]); len(fields) > 0 {
					d.bits = fields[0]
				}
			}
			if len(lines) > 1 {
				d.randomart = strings.Join(lines[1:], "\n")
			}
		}
		if d.bits == "" {
			d.bits = "?"
		}

		out, err := exec.Command("ssh-add", "-L").Output()
		if err != nil {
			ee, ok := err.(*exec.ExitError)
			switch {
			case ok && ee.ExitCode() == 1:
				d.agentStatus = "not loaded"
			case ok && ee.ExitCode() == 2:
				d.agentStatus = "agent unavailable"
			default:
				d.agentStatus = "agent error"
			}
		} else if sshAgentHasFingerprint(out, fingerprint) {
			d.agentStatus = "loaded"
		} else {
			d.agentStatus = "not loaded"
		}

		return sshDetailsMsg{details: d}
	}
}

func deleteSSHKeyCmd(privPath, pubPath, name string) tea.Cmd {
	return func() tea.Msg {
		var firstErr error
		for _, p := range []string{privPath, pubPath} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		return sshDeleteDoneMsg{name: name, err: firstErr}
	}
}

func reloadSSHKeysCmd() tea.Msg {
	keys, err := LoadSSHKeys()
	return sshKeysReloadedMsg{keys: keys, err: err}
}

func yankCmd(path, filename string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return sshClipboardDoneMsg{filename: filename, err: err}
		}

		tool, args := clipboardTool()
		if tool == "" {
			return sshClipboardDoneMsg{filename: filename, err: errors.New("no clipboard tool found (install wl-clipboard, xclip, or xsel)")}
		}

		c := exec.Command(tool, args...)
		c.Stdin = strings.NewReader(string(data))

		return sshClipboardDoneMsg{filename: filename, err: c.Run()}
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
