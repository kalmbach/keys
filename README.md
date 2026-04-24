keys is a terminal UI for browsing the local GPG keyring and performing common key maintenance tasks.

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
