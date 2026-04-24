`keys` is a terminal UI for browsing local GPG and SSH keys and performing common key maintenance tasks.

## Usage

Run `keys` to open the TUI. `keys --version` prints the version and exits.

Key bindings:

| key       | action                            |
|-----------|-----------------------------------|
| `tab`     | switch between GPG and SSH views  |
| `↑` / `k` | move up                           |
| `↓` / `j` | move down                         |
| `e`       | edit expiry (GPG only)            |
| `y`       | yank public key to clipboard (SSH only) |
| `?`       | toggle help                       |
| `q`, `esc`| quit                              |

GPG keys are loaded via `libgpgme`.

SSH keys are read from `~/.ssh/*.pub` (certificates and non-`.pub` files are skipped).

## Install

One-liner (Ubuntu/Debian):

```
curl -fsSL https://raw.githubusercontent.com/kalmbach/keys/main/install.sh | bash
```

The script checks for `libgpgme-dev`, offers to `sudo apt-get install` it if
missing, and then runs `go install github.com/kalmbach/keys@latest`. A Go
toolchain is required; install one from https://go.dev/dl/ first.

Prefer to do it by hand:

```
sudo apt-get install -y libgpgme-dev
go install github.com/kalmbach/keys@latest
```

The binary lands in `$(go env GOPATH)/bin` — make sure that directory is on
your `PATH`.
