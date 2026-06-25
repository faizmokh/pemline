package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/atotto/clipboard"
)

var version = "dev"

func main() {
	fileFlag := flag.String("f", "", "path to PEM private key file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("pemline", version)
		return
	}

	raw, err := readInput(*fileFlag)
	if err != nil {
		fail(err)
	}

	inlined, err := inlineKey(raw)
	if err != nil {
		fail(err)
	}

	fmt.Println(inlined)
}

func readInput(fileFlag string) ([]byte, error) {
	if fileFlag != "" {
		return os.ReadFile(fileFlag)
	}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return io.ReadAll(os.Stdin)
	}
	s, err := clipboard.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("clipboard: %w", err)
	}
	if s == "" {
		return nil, errors.New("no input: provide -f <file>, pipe via stdin, or copy a key to the clipboard")
	}
	return []byte(s), nil
}

func inlineKey(raw []byte) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	block, _ := pem.Decode(trimmed)
	if block == nil {
		return "", errors.New("not a valid PEM block")
	}

	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
				return "", fmt.Errorf("not a valid private key: %w", err)
			}
		}
	}

	return strings.ReplaceAll(string(trimmed), "\n", `\n`), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "pemline:", err)
	os.Exit(1)
}
