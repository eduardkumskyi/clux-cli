package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestEmbeddedReleaseKeysParse(t *testing.T) {
	if len(TrustedKeys()) == 0 {
		t.Fatal("no release key embedded")
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv := testKey(t)
	otherPub, otherPriv := testKey(t)
	sums := []byte(strings.Repeat("a", 64) + "  clux_darwin_arm64.tar.gz\n")
	sig := Sign(priv, "v0.7.0", sums)
	keys := []ed25519.PublicKey{pub}

	if err := VerifySignature("v0.7.0", sums, sig, keys); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	// Any trusted key will do (rotation keeps two for a while).
	if err := VerifySignature("v0.7.0", sums, sig, []ed25519.PublicKey{otherPub, pub}); err != nil {
		t.Fatalf("second trusted key: %v", err)
	}
	for name, tc := range map[string]struct {
		tag  string
		sums []byte
		sig  []byte
		keys []ed25519.PublicKey
	}{
		"other key":          {"v0.7.0", sums, Sign(otherPriv, "v0.7.0", sums), keys},
		"tampered checksums": {"v0.7.0", append([]byte("b"), sums[1:]...), sig, keys},
		// An old release's signed checksums replayed under another tag.
		"other tag":      {"v0.8.0", sums, sig, keys},
		"garbage":        {"v0.7.0", sums, []byte("not base64!"), keys},
		"truncated":      {"v0.7.0", sums, sig[:20], keys},
		"empty":          {"v0.7.0", sums, nil, keys},
		"no keys at all": {"v0.7.0", sums, sig, nil},
	} {
		if err := VerifySignature(tc.tag, tc.sums, tc.sig, tc.keys); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// signedRelease serves tag's darwin/arm64 archive and checksums.txt, plus
// checksums.txt.sig when sig is non-nil.
func signedRelease(t *testing.T, tag string, sig func(sums []byte) []byte) (*Client, []byte) {
	t.Helper()
	archive := tarGz(t, map[string][]byte{"clux": []byte("signed clux")})
	sums := []byte(sum(archive) + "  clux_darwin_arm64.tar.gz\n")
	assets := map[string][]byte{"clux_darwin_arm64.tar.gz": archive}
	if sig != nil {
		assets[SignatureAsset] = sig(sums)
	}
	return fakeGitHub(t, tag, assets, string(sums)), sums
}

func TestDownloadVerifiesTheSignature(t *testing.T) {
	pub, priv := testKey(t)
	_, otherPriv := testKey(t)
	ctx := context.Background()

	// Good: accepted on both paths, reported signed.
	c, _ := signedRelease(t, "v0.7.0", func(s []byte) []byte { return Sign(priv, "v0.7.0", s) })
	c.Keys = []ed25519.PublicKey{pub}
	for _, allowUnsigned := range []bool{true, false} {
		got, signed, err := c.Download(ctx, "v0.7.0", allowUnsigned)
		if err != nil || !signed || string(got) != "signed clux" {
			t.Fatalf("allowUnsigned=%v: %q signed=%v %v", allowUnsigned, got, signed, err)
		}
	}

	// Bad: refused on both paths, never downgraded to checksum-only.
	c, _ = signedRelease(t, "v0.7.0", func(s []byte) []byte { return Sign(otherPriv, "v0.7.0", s) })
	c.Keys = []ed25519.PublicKey{pub}
	for _, allowUnsigned := range []bool{true, false} {
		if _, _, err := c.Download(ctx, "v0.7.0", allowUnsigned); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("allowUnsigned=%v: want a signature error, got %v", allowUnsigned, err)
		}
	}

	// Missing, on a release that must be signed: refused on both paths.
	c, _ = signedRelease(t, "v0.7.0", nil)
	c.Keys = []ed25519.PublicKey{pub}
	for _, allowUnsigned := range []bool{true, false} {
		if _, _, err := c.Download(ctx, "v0.7.0", allowUnsigned); !errors.Is(err, ErrUnsigned) {
			t.Fatalf("allowUnsigned=%v: want ErrUnsigned, got %v", allowUnsigned, err)
		}
	}

	// Missing, on a release from before signing: only the CLI path takes
	// it, on its checksum alone.
	c, _ = signedRelease(t, "v0.6.0", nil)
	c.Keys = []ed25519.PublicKey{pub}
	got, signed, err := c.Download(ctx, "v0.6.0", true)
	if err != nil || signed || string(got) != "signed clux" {
		t.Fatalf("legacy release: %q signed=%v %v", got, signed, err)
	}
	if _, _, err := c.Download(ctx, "v0.6.0", false); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("the root path must refuse an unsigned release, got %v", err)
	}
}

func TestValidTag(t *testing.T) {
	for _, tag := range []string{"v0.7.0", "v1.0.0", "v10.20.30", "v0.7.0-rc.1", "v1.2.3-beta"} {
		if !ValidTag(tag) {
			t.Errorf("%q refused", tag)
		}
	}
	for _, tag := range []string{
		"", "0.7.0", "v0.7", "v0.7.0.1", "v01.2.3", "v0.7.0-", "v0.7.0-rc..1", "v0.7.0+build",
		"v0.7.0/../../x", "../v0.7.0", "v0.7.0\n", " v0.7.0", "latest", "v0.7.0-" + strings.Repeat("a", 64),
	} {
		if ValidTag(tag) {
			t.Errorf("%q accepted", tag)
		}
	}
	c := &Client{GOOS: "darwin", GOARCH: "arm64", DownloadBase: "http://127.0.0.1:1"}
	if _, _, err := c.Download(context.Background(), "v0.7.0/../../evil", true); err == nil || !strings.Contains(err.Error(), "not a release tag") {
		t.Fatalf("Download must validate the tag first, got %v", err)
	}
}
