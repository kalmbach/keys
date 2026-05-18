`keys` is a terminal UI for browsing local GPG and SSH keys and performing common key maintenance tasks.

## Install

One-liner:

```
curl -fsSL https://raw.githubusercontent.com/kalmbach/keys/main/install.sh | bash
```

The script checks for the Go toolchain, warns if `gpg` or `ssh-keygen` are
missing, and runs `go install github.com/kalmbach/keys@latest`. A Go toolchain
is required; install one from https://go.dev/dl/ first.

Prefer to do it by hand:

```
go install github.com/kalmbach/keys@latest
```

The binary lands in `$(go env GOPATH)/bin` — make sure that directory is on
your `PATH`.

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
| `enter`   | show key details                  |
| `y`       | yank public key to clipboard      |
| `g`       | generate new key                  |
| `e`       | edit expiry                       |
| `p`       | change passphrase                 |
| `d`       | delete key pair (pub row only, type the Key ID to confirm) |

SSH keys

| key       | action                            |
|-----------|-----------------------------------|
| `enter`   | show key details                  |
| `y`       | yank public key to clipboard      |
| `g`       | generate new key                  |
| `c`       | change comment                    |
| `p`       | change passphrase                 |
| `d`       | delete key pair (type the filename to confirm) |

GPG keys are loaded by shelling out to `gpg --with-colons` and parsing the
output. SSH keys are read from `~/.ssh/*.pub` (certificates and non-`.pub`
files are skipped). Both `gpg` and `ssh-keygen` must be available on `PATH`
at runtime — almost always already the case on Linux and macOS.

## Version

Current Version 0.6.0
