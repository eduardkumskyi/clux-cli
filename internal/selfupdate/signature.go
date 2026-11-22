package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Release signing. The release workflow signs every release's checksums.txt
// with an ed25519 key (tools/releasesign, run by goreleaser) and publishes
// the signature as checksums.txt.sig: one line, the base64 of the 64-byte
// signature. The signed message is not checksums.txt alone but
//
//	"clux-release-v1\n" + tag + "\n" + checksums.txt
//
// so a signature also says which release the checksums belong to: an old
// release's signed checksums.txt served under a newer tag does not verify
// (the archive names carry no version, so the checksums alone would).
//
// A signature is accepted from any key in TrustedKeys; rotating the key is
// adding the new one here, releasing (signed with the old key), then
// switching the workflow secret to the new key and later dropping the old
// one from the list (see README).

// SignatureAsset is the release asset holding checksums.txt's signature.
const SignatureAsset = "checksums.txt.sig"

// FirstSignedRelease is the first release published with SignatureAsset.
// Only an older release may lack it, and only `clux update` (never the root
// daemon) installs one without a signature.
const FirstSignedRelease = "v0.7.0"

const signatureContext = "clux-release-v1"

// trustedKeysBase64 are the release public keys (base64, 32 bytes each).
var trustedKeysBase64 = []string{
	"VZ+zCxIRJnC+qRRk299/ouc+gH0R8DKaV3a6OgwCs+A=", // 2026-11 key; private half: secret CLUX_RELEASE_SIGNING_KEY
}

// TrustedKeys are the public keys a release signature may come from.
func TrustedKeys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(trustedKeysBase64))
	for _, k := range trustedKeysBase64 {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			panic(fmt.Sprintf("selfupdate: malformed embedded release key %q", k))
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys
}

// ErrUnsigned: the release has no SignatureAsset.
var ErrUnsigned = errors.New("the release is not signed")

func signedMessage(tag string, checksums []byte) []byte {
	msg := make([]byte, 0, len(signatureContext)+len(tag)+2+len(checksums))
	msg = append(msg, signatureContext+"\n"+tag+"\n"...)
	return append(msg, checksums...)
}

// Sign returns the SignatureAsset content for release tag's checksums.txt.
func Sign(key ed25519.PrivateKey, tag string, checksums []byte) []byte {
	sig := ed25519.Sign(key, signedMessage(tag, checksums))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// VerifySignature checks sigFile (SignatureAsset's content) over release
// tag's checksums.txt against keys.
func VerifySignature(tag string, checksums, sigFile []byte, keys []ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigFile)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s of %s is malformed", SignatureAsset, tag)
	}
	msg := signedMessage(tag, checksums)
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("%s of %s does not verify against the clux release key; refusing it", SignatureAsset, tag)
}

// releaseTag: "v" + MAJOR.MINOR.PATCH without leading zeros, optionally a
// "-suffix" of dot-separated alphanumerics (goreleaser's prereleases).
var releaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// ValidTag reports whether tag has a release tag's shape ("v0.7.0"). It
// ends up in download URLs and in root-owned files, so nothing else is let
// through.
func ValidTag(tag string) bool {
	return len(tag) <= 64 && !strings.ContainsAny(tag, "/\\") && releaseTag.MatchString(tag)
}
