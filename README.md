# pemline

Inline a PEM private key into a single `\n`-escaped line — for environment
variables, config files, CI secrets, and anywhere you need a key on one line.

```sh
$ pemline -f key.pem
-----BEGIN PRIVATE KEY-----\nMIGTAgEA...\nbVWoHuAe\n-----END PRIVATE KEY-----
```

The key is **validated** (PKCS#8, PKCS#1, or SEC1/EC) before being transformed,
so you get a clear error instead of silently shipping a malformed key.

## Install

### Homebrew (macOS / Linux)

```sh
brew install faizmokh/tap/pemline
```

### Go

```sh
go install github.com/faizmokh/pemline@latest
```

### Build from source

```sh
git clone https://github.com/faizmokh/pemline.git
cd pemline
go build -o pemline .
```

Prebuilt binaries for macOS, Linux, and Windows (amd64 + arm64) are available
on the [releases page](https://github.com/faizmokh/pemline/releases).

## Usage

```
pemline [-f path] [--version]
```

Input is resolved in priority order — the first available source wins:

| # | Source      | How                                        |
|---|-------------|--------------------------------------------|
| 1 | File        | `pemline -f key.pem`                       |
| 2 | Stdin (pipe)| `cat key.pem \| pemline`                   |
| 3 | Clipboard   | copy the key, then run `pemline`           |

### Flags

- `-f path` — read the key from a file
- `--version` — print version and exit

### Examples

```sh
pemline -f key.pem                 # from a file
cat key.pem | pemline              # from a pipe
pemline                            # from the clipboard

pemline -f key.pem | pbcopy        # macOS: copy result to clipboard
pemline -f key.pem | xclip -sel c  # Linux: copy result to clipboard
pemline -f key.pem > key.env       # save to a file
```

### Error handling

`pemline` exits non-zero with a message on stderr when the input isn't a valid
PEM block or a parseable private key:

```sh
$ pemline -f not-a-key.txt
pemline: not a valid PEM block
```

## Why

Most services accept private keys on a single line with `\n` escapes (e.g. Vercel,
Railway, Google Cloud, JWT signing). Manually joining lines is error-prone and
strips the `BEGIN`/`END` markers. `pemline` keeps the markers intact and validates
the key, so the inlined value is always correct.

## Supported key formats

- PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
- PKCS#1 RSA (`-----BEGIN RSA PRIVATE KEY-----`)
- SEC1 EC (`-----BEGIN EC PRIVATE KEY-----`)

## Development

```sh
go test -v ./...      # run the test suite
goreleaser check      # validate release config
```

Releases are cut with [GoReleaser](https://goreleaser.com); see
[`.goreleaser.yaml`](.goreleaser.yaml).

## License

MIT
