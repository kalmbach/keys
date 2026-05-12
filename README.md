`keys` is a terminal UI for browsing local GPG and SSH keys and performing common key maintenance tasks.

## Usage

Run `keys` to open the TUI. `keys --version` prints the version and exits.

Key bindings:

Global

| key       | action                            |
|-----------|-----------------------------------|
| `tab`     | switch between GPG and SSH views  |
| `↑` / `k` | move up                           |
| `↓` / `j` | move down                         |
| `?`       | toggle help                       |
| `q`, `esc`| quit                              |

GPG keys

| key       | action                            |
|-----------|-----------------------------------|
| `e`       | edit expiry                       |

SSH keys

| key       | action                            |
|-----------|-----------------------------------|
| `enter`   | show key details                  |
| `y`       | yank public key to clipboard      |
| `g`       | generate new key                  |
| `c`       | change comment                    |
| `p`       | change passphrase                 |
| `d`       | delete key pair                   |

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

## Version

Current Version 0.4.0
