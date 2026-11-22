// Command releasesign makes and checks the release signature
// (checksums.txt.sig, see internal/selfupdate/signature.go).
//
//	releasesign keygen -out <file>      new key: private seed (base64) to <file>
//	                                    (0600), public key printed
//	releasesign sign -tag vX.Y.Z -in checksums.txt -out checksums.txt.sig
//	                                    signs with $CLUX_RELEASE_SIGNING_KEY
//	                                    (or -key-file <file>)
//	releasesign verify -tag vX.Y.Z -in checksums.txt -sig checksums.txt.sig
//
// The release workflow runs `sign` through goreleaser. It refuses to sign
// with a key the clux binary does not trust, so a wrong secret fails the
// release before anything is published.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

const keyEnv = "CLUX_RELEASE_SIGNING_KEY"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasesign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: releasesign <keygen|sign|verify> ...")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	tag := fs.String("tag", "", "release tag")
	in := fs.String("in", "", "checksums.txt")
	out := fs.String("out", "", "output file")
	sig := fs.String("sig", "", "checksums.txt.sig")
	keyFile := fs.String("key-file", "", "sign: read the base64 seed from this file instead of $"+keyEnv)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		if *out == "" {
			return errors.New("keygen needs -out")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	case "sign":
		if !selfupdate.ValidTag(*tag) || *in == "" || *out == "" {
			return errors.New("sign needs -tag vX.Y.Z, -in and -out")
		}
		encoded := os.Getenv(keyEnv)
		if *keyFile != "" {
			b, err := os.ReadFile(*keyFile)
			if err != nil {
				return err
			}
			encoded = string(b)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("$%s must hold the base64 ed25519 seed (%d bytes)", keyEnv, ed25519.SeedSize)
		}
		key := ed25519.NewKeyFromSeed(seed)
		checksums, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		signature := selfupdate.Sign(key, *tag, checksums)
		if err := selfupdate.VerifySignature(*tag, checksums, signature, selfupdate.TrustedKeys()); err != nil {
			return fmt.Errorf("$%s is not a key clux trusts (update TrustedKeys first): %w", keyEnv, err)
		}
		return os.WriteFile(*out, signature, 0o644)
	case "verify":
		if *tag == "" || *in == "" || *sig == "" {
			return errors.New("verify needs -tag, -in and -sig")
		}
		checksums, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		signature, err := os.ReadFile(*sig)
		if err != nil {
			return err
		}
		if err := selfupdate.VerifySignature(*tag, checksums, signature, selfupdate.TrustedKeys()); err != nil {
			return err
		}
		fmt.Println("signature OK")
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}
