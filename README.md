# pemline

Inline a PEM private key into a single `\n`-escaped line — handy for environment variables, config files, and anywhere you need a key on one line.

## Install

```sh
brew install faizmokh/tap/pemline
```

## Usage

```
pemline [-f file]
```

Input is resolved in priority order:
1. `-f path/to/key.pem` — read from a file
2. piped stdin — `cat key.pem | pemline`
3. system clipboard — fallback when neither is provided

The key is validated (PKCS#8, PKCS#1, or SEC1/EC) before being transformed.

### Examples

```sh
$ pemline -f key.pem
-----BEGIN PRIVATE KEY-----\nMIGTAgEA...\nbVWoHuAe\n-----END PRIVATE KEY-----

$ pemline -f key.pem | pbcopy   # copy to clipboard
```

## License

MIT
